import {
  cloneElement,
  isValidElement,
  useEffect,
  useId,
  useRef,
  type ReactElement,
  type ReactNode,
} from "react";
import {
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Search,
  SlidersHorizontal,
  X,
  Info,
} from "lucide-react";
import { Link, useLocation, useSearchParams } from "react-router-dom";

export function Badge({
  children,
  kind,
}: {
  children: ReactNode;
  kind?: string;
}) {
  const text = kind || String(children);
  const tone = /Critical|Fail|Error|Reopened|Still Open|Expired|BLOCK/.test(
    text,
  )
    ? "red"
    : /High|Degraded|Stale|Expiring|Pending|WARN|Unknown|Unverified/.test(text)
      ? "amber"
      : /Healthy|Verified|Pass|PASS|Active|Approved|Private|Blocked|Success/.test(
            text,
          )
        ? "green"
        : /Medium|In Progress|Review|Inferred/.test(text)
          ? "blue"
          : "gray";
  return (
    <span className={`cs-badge ${tone}`}>
      <span />
      {children}
    </span>
  );
}
export function Head({
  title,
  children,
  meta,
}: {
  title: string;
  children?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <header className="cs-head">
      <div>
        <h1>{title}</h1>
        {meta && <div className="cs-meta">{meta}</div>}
      </div>
      <div className="cs-actions">{children}</div>
    </header>
  );
}
export function Panel({
  title,
  action,
  children,
  className = "",
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`cs-panel ${className}`}>
      {title && (
        <div className="cs-panel-head">
          <h2>{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
export function Jump({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link className="cs-jump" to={to}>
      {children}
      <ArrowUpRight size={14} />
    </Link>
  );
}
export function Tabs({
  items,
  value,
  onChange,
}: {
  items: string[];
  value: string;
  onChange: (s: string) => void;
}) {
  return (
    <div className="cs-tabs" role="tablist" aria-label="Workspace views">
      {items.map((item, i) => (
        <button
          role="tab"
          aria-selected={value === item}
          tabIndex={value === item ? 0 : -1}
          key={item}
          className={value === item ? "active" : ""}
          onClick={() => onChange(item)}
          onKeyDown={(e) => {
            if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
              e.preventDefault();
              const next =
                e.key === "Home"
                  ? 0
                  : e.key === "End"
                    ? items.length - 1
                    : (i + (e.key === "ArrowRight" ? 1 : -1) + items.length) %
                      items.length;
              onChange(items[next]);
              (
                e.currentTarget.parentElement?.children[
                  next
                ] as HTMLButtonElement
              )?.focus();
            }
          }}
        >
          {item}
        </button>
      ))}
    </div>
  );
}
export function useFilters() {
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const current = useRef(params);
  current.current = params;
  const storageKey = `cs.filters.${location.pathname}`;
  useEffect(() => {
    try {
      if (location.search) sessionStorage.setItem(storageKey, location.search);
      else {
        const saved = sessionStorage.getItem(storageKey);
        if (saved) setParams(new URLSearchParams(saved), { replace: true });
      }
    } catch {
      /* URL filters still work when browser storage is unavailable. */
    }
  }, [location.search, storageKey, setParams]);
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(current.current);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("page");
    current.current = next;
    try {
      sessionStorage.setItem(storageKey, next.toString());
    } catch {
      /* In-memory fallback. */
    }
    setParams(next, { replace: true });
  };
  return {
    params,
    set,
    clear: () => {
      try {
        sessionStorage.removeItem(storageKey);
      } catch {
        /* In-memory fallback. */
      }
      current.current = new URLSearchParams();
      setParams({});
    },
  };
}
export function Filters({
  fields,
  placeholder = "Search...",
  filters,
}: {
  fields: Record<string, string[]>;
  placeholder?: string;
  filters: ReturnType<typeof useFilters>;
}) {
  const { params, set, clear } = filters;
  return (
    <div className="cs-filters">
      <div className="cs-filter-line">
        <label className="cs-search">
          <Search size={16} />
          <input
            aria-label={placeholder}
            placeholder={placeholder}
            value={params.get("q") || ""}
            onChange={(e) => set("q", e.target.value)}
          />
        </label>
        <SlidersHorizontal size={15} className="cs-muted" />
        {Object.entries(fields).map(([key, choices]) =>
          key === "severity" || key === "risk" ? (
            <details
              className="cs-multi"
              key={key}
              onKeyDown={(event) => {
                if (event.key === "Escape") event.currentTarget.open = false;
              }}
            >
              <summary aria-label={`Filter ${key}`}>
                <span>
                  {params.get(key)?.split(",").join(", ") ||
                    key[0].toUpperCase() + key.slice(1)}
                </span>
                <ChevronDown size={12} />
              </summary>
              <div role="group" aria-label={`${key} choices`}>
                {choices.map((choice) => {
                  const selected = params.get(key)?.split(",") || [];
                  return (
                    <label key={choice}>
                      <input
                        type="checkbox"
                        checked={selected.includes(choice)}
                        onChange={() =>
                          set(
                            key,
                            (selected.includes(choice)
                              ? selected.filter((v) => v !== choice)
                              : [...selected, choice]
                            ).join(","),
                          )
                        }
                      />
                      {choice}
                    </label>
                  );
                })}
              </div>
            </details>
          ) : (
            <label key={key}>
              <span className="sr-only">{key}</span>
              <select
                aria-label={`Filter ${key}`}
                value={params.get(key) || ""}
                onChange={(e) => set(key, e.target.value)}
              >
                <option value="">{key[0].toUpperCase() + key.slice(1)}</option>
                {choices.map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
          ),
        )}
      </div>
      {params.size > 0 && (
        <div className="cs-chips">
          {Array.from(params.entries())
            .filter(([k]) => k !== "tab")
            .flatMap(([k, value]) =>
              (k === "severity" || k === "risk"
                ? value.split(",")
                : [value]
              ).map((v) => (
                <button
                  key={`${k}-${v}`}
                  onClick={() =>
                    set(
                      k,
                      k === "severity" || k === "risk"
                        ? value
                            .split(",")
                            .filter((x) => x !== v)
                            .join(",")
                        : "",
                    )
                  }
                >
                  {k}: {v}
                  <X size={12} />
                </button>
              )),
            )}
          <button
            className="clear"
            onClick={() => {
              clear();
            }}
          >
            Clear all
          </button>
        </div>
      )}
    </div>
  );
}
export function Table({
  headers,
  children,
  count,
  empty = false,
}: {
  headers: string[];
  children: ReactNode;
  count?: number;
  empty?: boolean;
}) {
  return (
    <>
      <div className="cs-table-scroll">
        <table className="cs-table">
          <thead>
            <tr>
              {headers.map((h) => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>{children}</tbody>
        </table>
      </div>
      {empty && (
        <Empty
          title="No matching records"
          text="Adjust filters, account, or server region. Missing collection evidence does not indicate a secure environment."
        />
      )}
      {count !== undefined && (
        <div className="cs-table-footer">
          <span>
            {count} record{count === 1 ? "" : "s"} · Current scope
          </span>
          <span>
            All records loaded <ChevronLeft size={14} />
            <b>1</b>
            <ChevronRight size={14} />
          </span>
        </div>
      )}
    </>
  );
}
export function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="cs-empty">
      <Info size={24} />
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
export function Notice({
  children,
  kind = "amber",
}: {
  children: ReactNode;
  kind?: string;
}) {
  return (
    <div className={`cs-notice ${kind}`}>
      <Info size={16} />
      <div>{children}</div>
    </div>
  );
}
export function Details({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="cs-details">
      {rows.map(([key, value]) => (
        <div key={key}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
export function Overlay({
  title,
  children,
  onClose,
  drawer = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  drawer?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    ref.current?.showModal();
    return () => {
      previous?.focus();
    };
  }, []);
  return (
    <dialog
      className={`cs-dialog ${drawer ? "drawer" : ""}`}
      ref={ref}
      aria-labelledby={id}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          const bounds = e.currentTarget.getBoundingClientRect();
          if (
            e.clientX < bounds.left ||
            e.clientX > bounds.right ||
            e.clientY < bounds.top ||
            e.clientY > bounds.bottom
          )
            onClose();
        }
      }}
    >
      <div className="cs-dialog-head">
        <h2 id={id}>{title}</h2>
        <button className="cs-icon" aria-label="Close dialog" onClick={onClose}>
          <X size={18} />
        </button>
      </div>
      <div className="cs-dialog-body">{children}</div>
    </dialog>
  );
}
export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <div className="cs-field">
      <label htmlFor={id}>{label}</label>
      {isValidElement(children)
        ? cloneElement(children as ReactElement<{ id?: string }>, { id })
        : children}
    </div>
  );
}
export function download(name: string, data: unknown, format = "json") {
  const rows = Array.isArray(data) ? data : [data];
  const cell = (v: unknown) => {
    const s = String(v ?? "");
    return `"${(/^[=+@\-\t\r]/.test(s) ? "'" : "") + s.replace(/"/g, '""')}"`;
  };
  const content =
    format === "csv"
      ? [
          Object.keys(rows[0] || {})
            .map(cell)
            .join(","),
          ...rows.map((row) =>
            Object.values(row)
              .map((v) => cell(typeof v === "object" ? JSON.stringify(v) : v))
              .join(","),
          ),
        ].join("\r\n")
      : JSON.stringify(data, null, 2);
  const url = URL.createObjectURL(
    new Blob([content], {
      type: format === "csv" ? "text/csv" : "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name}.${format}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
