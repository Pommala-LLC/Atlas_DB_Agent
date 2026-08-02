(() => {
  const form = document.getElementById('procedure-analysis-form');
  if (!form) return;
  const database = document.getElementById('database-type');
  const dialect = document.getElementById('declared-dialect');
  const sql = document.getElementById('sql-text');
  const count = document.getElementById('sql-count');
  const files = document.getElementById('files');
  const fileList = document.getElementById('file-list');
  const dropzone = document.getElementById('dropzone');
  const modeButtons = [...document.querySelectorAll('.mode-button[data-focus-target]')];

  const escapeHtml = value => String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch]));
  const formatBytes = value => value < 1024 ? `${value} B` : value < 1024 * 1024 ? `${(value / 1024).toFixed(1)} KB` : `${(value / (1024 * 1024)).toFixed(1)} MB`;

  function refreshDialect() {
    const option = database.options[database.selectedIndex];
    if (dialect) dialect.value = option && option.dataset.dialect ? option.dataset.dialect : '';
  }
  function refreshCount() { count.textContent = `${sql.value.length.toLocaleString()} characters`; }
  function refreshFiles() {
    const values = [...files.files];
    fileList.innerHTML = values.map(file => `<div class="compact-file-row"><span>${escapeHtml(file.name)}</span><small>${formatBytes(file.size)}</small></div>`).join('');
  }
  function focusTarget(targetId) {
    modeButtons.forEach(button => button.classList.toggle('active', button.dataset.focusTarget === targetId));
    const target = document.getElementById(targetId);
    if (targetId === 'files') dropzone.click();
    else target?.focus();
  }

  database.addEventListener('change', refreshDialect);
  sql.addEventListener('input', refreshCount);
  files.addEventListener('change', refreshFiles);
  modeButtons.forEach(button => button.addEventListener('click', () => focusTarget(button.dataset.focusTarget)));
  ['dragenter','dragover'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.add('dragover'); }));
  ['dragleave','drop'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.remove('dragover'); }));
  dropzone.addEventListener('drop', event => { files.files = event.dataTransfer.files; refreshFiles(); });
  form.addEventListener('submit', event => {
    if (!database.value) { event.preventDefault(); database.focus(); return; }
    if (!sql.value.trim() && files.files.length === 0) { event.preventDefault(); sql.focus(); }
  });
  refreshDialect(); refreshCount(); refreshFiles();
})();
