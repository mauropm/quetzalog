import json, random, subprocess, os, sys, threading, time, urllib.request
PORT=int(os.environ.get("QZ_PORT","18080")); BASE=f"http://127.0.0.1:{PORT}"
def pct(xs,q):
    x=sorted(xs); return x[min(len(x)-1,int(q*len(x)))]
def post(path, body, timeout=180):
    req=urllib.request.Request(BASE+path,data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
    t0=time.time(); r=urllib.request.urlopen(req,timeout=timeout); r.read(); return time.time()-t0
peak=0
def sampler():
    global peak
    while True:
        try: peak=max(peak,int(subprocess.check_output(["ps","-o","rss=","-p",os.environ["QZ_PID"]]).decode().split()[0]))
        except Exception: return
        time.sleep(0.05)
random.seed(1234)
events=[]
for i in range(20000):
    events.append({"timestamp":"2026-10-11T10:%02d:%02dZ"%((i//3600)%60,(i//60)%60),"source":"bench","source_type":"file:json","host":"host%d"%(i%50),"severity":random.choice(["info","info","info","warning","err","critical"]),"message":"benchmark event %d user=%s ip=10.0.0.%d action=login outcome=%s"%(i,random.choice(["alice","bob","carol","dave"]),i%255,random.choice(["success","failure"])),"attributes":{"user":random.choice(["alice","bob","carol","dave"]),"count":i%7,"service":random.choice(["ssh","web","db"])}})
th=threading.Thread(target=sampler,daemon=True); th.start()
t0=time.time()
lat=[post("/api/v1/events/batch",{"events":events[i:i+1000]}) for i in range(0,len(events),1000)]
wall=time.time()-t0
print("ingest_wall_s=%.2f"%(wall))
print("ingest_rate=%.1f"%(len(events)/wall))
print("batch_p50=%.4f batch_p95=%.4f batch_p99=%.4f"%(pct(lat,.5),pct(lat,.95),pct(lat,.99)))
single=[post("/api/v1/events",{"timestamp":"2026-10-11T10:00:00Z","source":"bench1","message":"single event %d"%i,"severity":"info","host":"h%d"%(i%10)}) for i in range(200)]
time.sleep(0.3)
print("peak_rss_kb=%d"%(peak))
print("single_p50=%.4f single_p95=%.4f single_p99=%.4f"%(pct(single,.5),pct(single,.95),pct(single,.99)))
q=[]
qs=["search * | head 50","search severity=err | head 100","bench | stats count by host","search source=bench | table id,host | head 20","search host=host1 | head 10"]
for i in range(100):
    q.append(post("/api/v1/search",{"query":qs[i%5],"limit":100}))
print("query_p50=%.4f query_p95=%.4f query_p99=%.4f"%(pct(q,.5),pct(q,.95),pct(q,.99)))
