import React, { useRef } from 'react';

const MAX = 400;

export default function CodeEditor({ value, onChange, disabled }) {
  const textareaRef = useRef(null);
  const count = value.length;
  const overLimit = count > MAX;
  const nearLimit = count >= 340;

  const counterColor = overLimit
    ? 'var(--danger)'
    : nearLimit
    ? 'var(--accent)'
    : 'var(--text-muted)';

  const borderColor = overLimit ? 'var(--danger)' : 'var(--border)';

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
          minHeight: 240,
          background: 'var(--bg-primary)',
          border: `1px solid ${borderColor}`,
          borderRadius: 'var(--radius)',
          color: 'var(--text-primary)',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.8rem',
          lineHeight: 1.65,
          padding: '14px 40px 32px 14px',
          resize: 'vertical',
          transition: 'border-color 0.12s',
          outline: 'none',
          display: 'block',
        }}
        onFocus={e => {
          if (!overLimit) e.target.style.borderColor = 'var(--accent)';
        }}
        onBlur={e => {
          e.target.style.borderColor = overLimit ? 'var(--danger)' : 'var(--border)';
        }}
      />

      {value.length > 0 && !disabled && (
        <button
          onClick={() => { onChange(''); textareaRef.current?.focus(); }}
          title="clear"
          style={{
            position: 'absolute',
            top: 10,
            right: 10,
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            fontSize: '1rem',
            lineHeight: 1,
            cursor: 'pointer',
            padding: '2px 4px',
            borderRadius: 3,
            transition: 'color 0.1s',
          }}
          onMouseEnter={e => e.target.style.color = 'var(--text-primary)'}
          onMouseLeave={e => e.target.style.color = 'var(--text-muted)'}
        >
          ×
        </button>
      )}

      <span style={{
        position: 'absolute',
        bottom: 9,
        right: 11,
        fontSize: '0.7rem',
        fontFamily: 'var(--font-mono)',
        color: counterColor,
        userSelect: 'none',
        transition: 'color 0.12s',
      }}>
        {count}/{MAX}
      </span>
    </div>
  );
}
