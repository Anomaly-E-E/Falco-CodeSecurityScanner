import React, { useRef } from 'react';

export default function CodeEditor({ value, onChange, disabled }) {
  const textareaRef = useRef(null);
  const count = value.length;

  const counterColor = 'var(--text-muted)';
  const borderColor = 'var(--border)';

  return (
    <div style={{ position: 'relative' }}>
      <textarea
        ref={textareaRef}
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={disabled}
        placeholder="paste your code here..."
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        style={{
          width: '100%',
          minHeight: 260,
          background: 'var(--bg-code)',
          border: `1px solid ${borderColor}`,
          borderRadius: 'var(--radius-lg)',
          color: 'var(--text-primary)',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.82rem',
          lineHeight: 1.7,
          padding: '16px 44px 36px 16px',
          resize: 'vertical',
          transition: 'border-color var(--duration-fast), box-shadow var(--duration-fast)',
          outline: 'none',
          display: 'block',
        }}
        onFocus={e => {
          e.target.style.borderColor = 'var(--accent)';
          e.target.style.boxShadow = '0 0 0 3px var(--accent-dim)';
        }}
        onBlur={e => {
          e.target.style.borderColor = overLimit ? 'var(--danger)' : 'var(--border)';
          e.target.style.boxShadow = 'none';
        }}
      />

      {value.length > 0 && !disabled && (
        <button
          onClick={() => { onChange(''); textareaRef.current?.focus(); }}
          title="clear"
          style={{
            position: 'absolute',
            top: 12,
            right: 12,
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            fontSize: '1.1rem',
            lineHeight: 1,
            cursor: 'pointer',
            padding: '2px 6px',
            borderRadius: 'var(--radius-sm)',
            transition: 'color var(--duration-fast)',
          }}
          onMouseEnter={e => e.target.style.color = 'var(--text-primary)'}
          onMouseLeave={e => e.target.style.color = 'var(--text-muted)'}
        >
          ×
        </button>
      )}

      <span style={{
        position: 'absolute',
        bottom: 12,
        right: 14,
        fontSize: '0.72rem',
        fontFamily: 'var(--font-mono)',
        color: counterColor,
        userSelect: 'none',
        transition: 'color var(--duration-fast)',
        letterSpacing: '0.02em',
      }}>
        {count} chars
      </span>
    </div>
  );
}
