export default function Panel({ title, action, children, className = '', ...rest }) {
  return (
    <section className={`panel ${className}`} {...rest}>
      {(title || action) && (
        <header className="panel__header">
          {title && <h2 className="panel__title">{title}</h2>}
          {action && <div className="panel__action">{action}</div>}
        </header>
      )}
      <div className="panel__body">{children}</div>
    </section>
  );
}
