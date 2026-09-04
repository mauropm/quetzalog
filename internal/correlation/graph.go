package correlation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"quetzalog/pkg/event"
	"time"
)

type EntityType string

const (
	EntityTypeIP      EntityType = "ip"
	EntityTypeUser    EntityType = "user"
	EntityTypeHost    EntityType = "host"
	EntityTypeProcess EntityType = "process"
	EntityTypeFile    EntityType = "file"
	EntityTypeDomain  EntityType = "domain"
	EntityTypeEmail   EntityType = "email"
	EntityTypeSession EntityType = "session"
	EntityTypeTraceID EntityType = "trace_id"
)

type Entity struct {
	ID        string
	Type      EntityType
	Value     string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
	Metadata  string
}

type Relationship struct {
	ID        string
	FromType  EntityType
	FromValue string
	ToType    EntityType
	ToValue   string
	Relation  string
	Weight    int
	CreatedAt time.Time
}

type EntityNeighbor struct {
	Entity   Entity
	Relation string
}

type TraverseNode struct {
	Entity   Entity
	Relation string
	Depth    int
}

type Graph struct {
	db *sql.DB
}

func NewGraph(db *sql.DB) *Graph {
	return &Graph{db: db}
}

func (g *Graph) initTables(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS entities (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			count INTEGER NOT NULL DEFAULT 1,
			metadata TEXT,
			UNIQUE(type, value)
		)`,
		`CREATE TABLE IF NOT EXISTS relationships (
			id TEXT PRIMARY KEY,
			from_type TEXT NOT NULL,
			from_value TEXT NOT NULL,
			to_type TEXT NOT NULL,
			to_value TEXT NOT NULL,
			relation TEXT NOT NULL,
			weight INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			UNIQUE(from_type, from_value, to_type, to_value, relation)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_entities_type_value ON entities(type, value)`,
		`CREATE INDEX IF NOT EXISTS idx_relationships_from ON relationships(from_type, from_value)`,
		`CREATE INDEX IF NOT EXISTS idx_relationships_to ON relationships(to_type, to_value)`,
		`CREATE INDEX IF NOT EXISTS idx_relationships_relation ON relationships(relation)`,
		`CREATE INDEX IF NOT EXISTS idx_relationships_created ON relationships(created_at)`,
	}

	for _, q := range queries {
		if _, err := g.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("execute migration: %w", err)
		}
	}

	return nil
}

func (g *Graph) UpsertEntity(ctx context.Context, entity *Entity) error {
	if err := g.initTables(ctx); err != nil {
		return err
	}

	if entity.ID == "" {
		entity.ID = event.GenerateEventID()
	}
	if entity.FirstSeen.IsZero() {
		entity.FirstSeen = time.Now().UTC()
	}
	if entity.LastSeen.IsZero() {
		entity.LastSeen = entity.FirstSeen
	}

	var metadataJSON string
	if entity.Metadata != "" {
		data, err := json.Marshal(entity.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		metadataJSON = string(data)
	} else {
		metadataJSON = "null"
	}

	_, err := g.db.ExecContext(ctx,
		`INSERT INTO entities (id, type, value, first_seen, last_seen, count, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(type, value) DO UPDATE SET
			last_seen = excluded.last_seen,
			count = count + 1,
			metadata = excluded.metadata`,
		entity.ID, entity.Type, entity.Value,
		entity.FirstSeen.Format(time.RFC3339), entity.LastSeen.Format(time.RFC3339),
		entity.Count, metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert entity: %w", err)
	}

	return nil
}

func (g *Graph) AddRelationship(ctx context.Context, rel *Relationship) error {
	if err := g.initTables(ctx); err != nil {
		return err
	}

	if rel.ID == "" {
		rel.ID = event.GenerateEventID()
	}
	if rel.Weight == 0 {
		rel.Weight = 1
	}
	if rel.CreatedAt.IsZero() {
		rel.CreatedAt = time.Now().UTC()
	}

	_, err := g.db.ExecContext(ctx,
		`INSERT INTO relationships (id, from_type, from_value, to_type, to_value, relation, weight, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(from_type, from_value, to_type, to_value, relation) DO UPDATE SET
			weight = weight + excluded.weight`,
		rel.ID, rel.FromType, rel.FromValue, rel.ToType, rel.ToValue, rel.Relation, rel.Weight,
		rel.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert relationship: %w", err)
	}

	return nil
}

func (g *Graph) GetEntity(ctx context.Context, entityType EntityType, value string) (*Entity, error) {
	e := &Entity{}
	err := g.db.QueryRowContext(ctx,
		`SELECT id, type, value, first_seen, last_seen, count, metadata FROM entities WHERE type = ? AND value = ?`,
		entityType, value,
	).Scan(&e.ID, &e.Type, &e.Value, &e.FirstSeen, &e.LastSeen, &e.Count, &e.Metadata)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query entity: %w", err)
	}

	return e, nil
}

func (g *Graph) GetNeighbors(ctx context.Context, entityType EntityType, value string, depth int) ([]EntityNeighbor, error) {
	if depth <= 0 {
		return nil, nil
	}

	rows, err := g.db.QueryContext(ctx,
		`SELECT e.id, e.type, e.value, e.first_seen, e.last_seen, e.count, e.metadata, r.relation
		 FROM relationships r
		 LEFT JOIN entities e ON (e.type = r.to_type AND e.value = r.to_value)
		 WHERE r.from_type = ? AND r.from_value = ?
		 UNION
		 SELECT e.id, e.type, e.value, e.first_seen, e.last_seen, e.count, e.metadata, r.relation
		 FROM relationships r
		 LEFT JOIN entities e ON (e.type = r.from_type AND e.value = r.from_value)
		 WHERE r.to_type = ? AND r.to_value = ?`,
		entityType, value, entityType, value,
	)
	if err != nil {
		return nil, fmt.Errorf("query neighbors: %w", err)
	}
	defer rows.Close()

	var edges []EntityNeighbor
	for rows.Next() {
		var en EntityNeighbor
		err := rows.Scan(
			&en.Entity.ID,
			&en.Entity.Type,
			&en.Entity.Value,
			&en.Entity.FirstSeen,
			&en.Entity.LastSeen,
			&en.Entity.Count,
			&en.Entity.Metadata,
			&en.Relation,
		)
		if err != nil {
			return nil, fmt.Errorf("scan neighbor: %w", err)
		}
		edges = append(edges, en)
	}

	if depth > 1 {
		for _, n := range edges {
			if n.Entity.Value == "" {
				continue
			}
			subNeighbors, err := g.GetNeighbors(ctx, n.Entity.Type, n.Entity.Value, depth-1)
			if err != nil {
				return nil, err
			}
			edges = append(edges, subNeighbors...)
		}
	}

	return edges, rows.Err()
}

func (g *Graph) GetRelatedEvents(ctx context.Context, entityType EntityType, value string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT DISTINCT e.id FROM events e
		WHERE
			(? = ? AND e.source_ip = ?) OR
			(? = ? AND e.destination_ip = ?) OR
			(? = ? AND e.user = ?) OR
			(? = ? AND e.host = ?) OR
			(? = ? AND e.trace_id = ?) OR
			(? = ? AND e.process = ?) OR
			(? = ? AND e.file_path = ?) OR
			(? = ? AND e.email IS NOT NULL AND e.email = ?)`

	rows, err := g.db.QueryContext(ctx, query,
		entityType, EntityTypeIP, value,
		entityType, EntityTypeIP, value,
		entityType, EntityTypeUser, value,
		entityType, EntityTypeHost, value,
		entityType, EntityTypeTraceID, value,
		entityType, EntityTypeProcess, value,
		entityType, EntityTypeFile, value,
		entityType, EntityTypeEmail, value,
	)
	if err != nil {
		return nil, fmt.Errorf("query related events: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan event id: %w", err)
		}
		ids = append(ids, id)
		if len(ids) >= limit {
			break
		}
	}

	return ids, rows.Err()
}

func (g *Graph) AddEntityFromEvent(ctx context.Context, ev *event.Event) error {
	entityFields := []struct {
		entityType EntityType
		value      string
	}{
		{EntityTypeIP, ev.SourceIP},
		{EntityTypeIP, ev.DestinationIP},
		{EntityTypeUser, ev.User},
		{EntityTypeHost, ev.Host},
		{EntityTypeProcess, ev.Process},
		{EntityTypeFile, ev.FilePath},
		{EntityTypeTraceID, ev.TraceID},
	}

	for _, f := range entityFields {
		if f.value == "" {
			continue
		}

		entity := &Entity{
			Type:      f.entityType,
			Value:     f.value,
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
			Count:     1,
		}

		if err := g.UpsertEntity(ctx, entity); err != nil {
			return fmt.Errorf("upsert entity %s/%s: %w", f.entityType, f.value, err)
		}
	}

	if ev.SourceIP != "" && ev.DestinationIP != "" {
		rel := &Relationship{
			FromType:  EntityTypeIP,
			FromValue: ev.SourceIP,
			ToType:    EntityTypeIP,
			ToValue:   ev.DestinationIP,
			Relation:  "connected_to",
			Weight:    1,
			CreatedAt: time.Now().UTC(),
		}
		if err := g.AddRelationship(ctx, rel); err != nil {
			return fmt.Errorf("add relationship: %w", err)
		}
	}

	if ev.User != "" && ev.Host != "" {
		rel := &Relationship{
			FromType:  EntityTypeUser,
			FromValue: ev.User,
			ToType:    EntityTypeHost,
			ToValue:   ev.Host,
			Relation:  "auth_from",
			Weight:    1,
			CreatedAt: time.Now().UTC(),
		}
		if err := g.AddRelationship(ctx, rel); err != nil {
			return fmt.Errorf("add relationship: %w", err)
		}
	}

	if ev.Host != "" && ev.Process != "" {
		rel := &Relationship{
			FromType:  EntityTypeHost,
			FromValue: ev.Host,
			ToType:    EntityTypeProcess,
			ToValue:   ev.Process,
			Relation:  "executed",
			Weight:    1,
			CreatedAt: time.Now().UTC(),
		}
		if err := g.AddRelationship(ctx, rel); err != nil {
			return fmt.Errorf("add relationship: %w", err)
		}
	}

	if ev.Host != "" && ev.FilePath != "" {
		rel := &Relationship{
			FromType:  EntityTypeHost,
			FromValue: ev.Host,
			ToType:    EntityTypeFile,
			ToValue:   ev.FilePath,
			Relation:  "accessed",
			Weight:    1,
			CreatedAt: time.Now().UTC(),
		}
		if err := g.AddRelationship(ctx, rel); err != nil {
			return fmt.Errorf("add relationship: %w", err)
		}
	}

	return nil
}

func (g *Graph) Traverse(ctx context.Context, entityType EntityType, value string, depth int) ([]TraverseNode, error) {
	if depth <= 0 {
		return nil, nil
	}

	visited := make(map[string]bool)
	var result []TraverseNode

	var visitFn func(current EntityType, currentVal string, currentDepth int, relation string)
	visitFn = func(current EntityType, currentVal string, currentDepth int, relation string) {
		key := string(current) + ":" + currentVal
		if visited[key] {
			return
		}
		visited[key] = true

		node := TraverseNode{
			Entity: Entity{
				Type:  current,
				Value: currentVal,
			},
			Relation: relation,
			Depth:    currentDepth,
		}
		result = append(result, node)

		if currentDepth >= depth {
			return
		}

		neighbors, err := g.GetNeighbors(ctx, current, currentVal, 1)
		if err != nil {
			return
		}

		for _, n := range neighbors {
			if n.Entity.Value == "" {
				continue
			}
			visitFn(n.Entity.Type, n.Entity.Value, currentDepth+1, n.Relation)
		}
	}

	visitFn(entityType, value, 0, "")

	return result, nil
}
