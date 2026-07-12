export default function EmptyState({ title, body, action }) {
  return (
    <div className="empty-state">
      <div className="empty-state__title">{title}</div>
      {body && <div className="empty-state__body">{body}</div>}
      {action && <div className="empty-state__action">{action}</div>}
    </div>
  );
}
