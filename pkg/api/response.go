package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Response represents a standard API response envelope.
type Response struct {
	Status  int             `json:"status"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Errors  []string        `json:"errors,omitempty"`
}

// Success creates a successful response with the given data.
func Success(data any) Response {
	var raw json.RawMessage
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return Response{
				Status:  http.StatusInternalServerError,
				Message: "failed to marshal response data",
				Errors:  []string{err.Error()},
			}
		}
		raw = b
	}
	return Response{
		Status:  http.StatusOK,
		Message: "OK",
		Data:    raw,
	}
}

// Error creates a response with an error status and message.
func Error(status int, msg string) Response {
	return Response{
		Status:  status,
		Message: msg,
		Errors:  []string{msg},
	}
}

// BadRequest creates a 400 Bad Request response.
func BadRequest(msg string) Response {
	if msg == "" {
		msg = "Bad request"
	}
	return Response{
		Status:  http.StatusBadRequest,
		Message: msg,
		Errors:  []string{msg},
	}
}

// NotFound creates a 404 Not Found response.
func NotFound(msg string) Response {
	if msg == "" {
		msg = "Resource not found"
	}
	return Response{
		Status:  http.StatusNotFound,
		Message: msg,
		Errors:  []string{msg},
	}
}

// InternalServerError creates a 500 Internal Server Error response.
func InternalServerError(msg string) Response {
	if msg == "" {
		msg = "Internal server error"
	}
	return Response{
		Status:  http.StatusInternalServerError,
		Message: msg,
		Errors:  []string{msg},
	}
}

// Unauthorized creates a 401 Unauthorized response.
func Unauthorized(msg string) Response {
	if msg == "" {
		msg = "Unauthorized"
	}
	return Response{
		Status:  http.StatusUnauthorized,
		Message: msg,
		Errors:  []string{msg},
	}
}

// Forbidden creates a 403 Forbidden response.
func Forbidden(msg string) Response {
	if msg == "" {
		msg = "Forbidden"
	}
	return Response{
		Status:  http.StatusForbidden,
		Message: msg,
		Errors:  []string{msg},
	}
}

// Conflict creates a 409 Conflict response.
func Conflict(msg string) Response {
	if msg == "" {
		msg = "Conflict"
	}
	return Response{
		Status:  http.StatusConflict,
		Message: msg,
		Errors:  []string{msg},
	}
}

// WriteResponse writes the API response to the HTTP response writer.
func WriteResponse(w http.ResponseWriter, r Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.Status)

	if err := json.NewEncoder(w).Encode(r); err != nil {
		fmt.Printf("quetzalog: failed to encode response: %v\n", err)
	}
}

// WriteJSON writes a raw JSON byte slice as the response body with the given status code.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Printf("quetzalog: failed to encode response: %v\n", err)
	}
}
