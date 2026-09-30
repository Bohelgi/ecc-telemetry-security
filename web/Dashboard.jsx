const { useEffect, useRef, useState } = React;

function useSharedChart(canvasRef, telemetry) {
    const chartRef = useRef(null);

    useEffect(() => {
        chartRef.current = new Chart(canvasRef.current.getContext("2d"), {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Потужність (Вт)",
                        data: [],
                        borderColor: "#4fd1c5",
                        backgroundColor: "rgba(79,209,197,0.1)",
                        tension: 0.25,
                        fill: true,
                        pointRadius: 0,
                    },
                ],
            },
            options: {
                animation: false,
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: "#8b98a5" }, grid: { color: "#22303c" } },
                    y: { ticks: { color: "#8b98a5" }, grid: { color: "#22303c" } },
                },
                plugins: { legend: { labels: { color: "#e6edf3" } } },
            },
        });
        return () => chartRef.current.destroy();
    }, []);

    useEffect(() => {
        if (!chartRef.current) return;
        chartRef.current.data.labels = telemetry.map((p) => new Date(p.t).toLocaleTimeString("uk-UA"));
        chartRef.current.data.datasets[0].data = telemetry.map((p) => p.P);
        chartRef.current.update("none");
    }, [telemetry]);
}

function StatTile({ label, value, unit }) {
    return (
        <div className="tile">
            <div className="label">{label}</div>
            <div className="value">
                {value}
                <span className="unit">{unit}</span>
            </div>
        </div>
    );
}

function EventRow({ event }) {
    const accepted = event.status === "accepted";
    return (
        <div className={`event ${accepted ? "accepted" : "rejected"}`}>
            <div>
                <strong>{accepted ? "ПРИЙНЯТО" : "ВІДХИЛЕНО"}</strong> #{event.seq} — {event.device}
                {!accepted && event.detail && <div className="reason">{event.detail}</div>}
            </div>
            <div className="meta">{event.t ? new Date(event.t).toLocaleTimeString("uk-UA") : ""}</div>
        </div>
    );
}

function Dashboard() {
    const [status, setStatus] = useState({ connectedDevices: [], totalAccepted: 0, totalRejected: 0 });
    const [telemetry, setTelemetry] = useState([]);
    const [events, setEvents] = useState([]);
    const [connected, setConnected] = useState(false);
    const canvasRef = useRef(null);
    useSharedChart(canvasRef, telemetry);

    useEffect(() => {
        let cancelled = false;

        async function poll() {
            try {
                const [s, t, e] = await Promise.all([
                    fetch("/api/status").then((r) => r.json()),
                    fetch("/api/telemetry").then((r) => r.json()),
                    fetch("/api/events").then((r) => r.json()),
                ]);
                if (cancelled) return;
                setStatus(s);
                setTelemetry(t);
                setEvents(e);
                setConnected(true);
            } catch {
                if (!cancelled) setConnected(false);
            }
        }

        poll();
        const id = setInterval(poll, 1000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, []);

    const last = telemetry[telemetry.length - 1];

    return (
        <>
            <h1>Secure Telemetry — панель моніторингу</h1>
            <div className="subtitle">
                ECDH + AES-256-GCM + ECDSA · React-версія (попередній перегляд без npm-збірки)
            </div>

            <div className="status-row">
                <div className="pill">
                    <span className={`dot ${connected ? "ok" : "bad"}`} />
                    {connected ? "Підключено до шлюзу" : "Немає з'єднання з шлюзом"}
                </div>
                <div className="pill">
                    Підключені пристрої: <strong>{status.connectedDevices.length}</strong>
                </div>
                <div className="pill">
                    Прийнято: <strong style={{ color: "var(--ok)" }}>{status.totalAccepted}</strong>
                </div>
                <div className="pill">
                    Відхилено: <strong style={{ color: "var(--bad)" }}>{status.totalRejected}</strong>
                </div>
            </div>

            <div className="grid">
                <StatTile label="Напруга" value={last ? last.U.toFixed(1) : "—"} unit="В" />
                <StatTile label="Струм" value={last ? last.I.toFixed(2) : "—"} unit="А" />
                <StatTile label="Потужність" value={last ? last.P.toFixed(1) : "—"} unit="Вт" />
                <StatTile label="Температура" value={last ? last.T.toFixed(1) : "—"} unit="°C" />
            </div>

            <div className="panels">
                <div className="panel">
                    <h2>Потужність у часі</h2>
                    <div id="chart-wrap">
                        <canvas ref={canvasRef}></canvas>
                    </div>
                </div>
                <div className="panel">
                    <h2>Стрічка подій</h2>
                    <div className="feed">
                        {events.length === 0 ? (
                            <div className="empty">Очікування даних від пристрою...</div>
                        ) : (
                            events
                                .slice()
                                .reverse()
                                .map((e, i) => <EventRow key={i} event={e} />)
                        )}
                    </div>
                </div>
            </div>
        </>
    );
}
