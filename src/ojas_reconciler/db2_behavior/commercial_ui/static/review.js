(() => {
  const body = document.body;
  const tabs = [...document.querySelectorAll('.review-tab')];
  const contents = [...document.querySelectorAll('.review-content')];
  const groupButtons = [...document.querySelectorAll('.review-dr-node')];
  const select = document.getElementById('review-run-select');

  const updateUrl = (key, value) => {
    const url = new URL(window.location.href);
    url.searchParams.set(key, value);
    history.replaceState({}, '', url);
  };

  const activateTab = (tabName, updateHistory = true) => {
    const tab = tabs.find(item => item.dataset.reviewTab === tabName) || tabs[0];
    if (!tab) return;
    tabs.forEach(item => item.classList.toggle('active', item === tab));
    contents.forEach(item => item.classList.toggle('active', item.id === `review-tab-${tab.dataset.reviewTab}`));
    body.dataset.selectedTab = tab.dataset.reviewTab;
    if (updateHistory) updateUrl('tab', tab.dataset.reviewTab);
  };

  const applyGroup = (group, updateHistory = true) => {
    body.dataset.selectedGroup = group;
    groupButtons.forEach(button => button.classList.toggle('active', button.dataset.reviewGroup === group));
    document.querySelectorAll('[data-review-group]').forEach(element => {
      if (element.classList.contains('review-dr-node')) return;
      const visible = element.dataset.reviewGroup === group || Boolean(element.closest('#review-tab-lineage'));
      element.classList.toggle('review-filtered', !visible);
    });
    if (updateHistory) updateUrl('group', group);
  };

  tabs.forEach(tab => tab.addEventListener('click', () => activateTab(tab.dataset.reviewTab)));
  groupButtons.forEach(button => button.addEventListener('click', () => applyGroup(button.dataset.reviewGroup)));
  document.querySelectorAll('[data-open-controls]').forEach(button => button.addEventListener('click', () => activateTab('controls')));
  document.querySelectorAll('.review-evidence-button').forEach(button => button.addEventListener('click', () => {
    const row = document.getElementById(button.dataset.evidenceTarget);
    if (row) row.classList.toggle('open');
  }));
  if (select) select.addEventListener('change', () => { window.location.href = `/review/${encodeURIComponent(select.value)}`; });


  const whatIfToggle = document.getElementById('review-what-if-toggle');
  const whatIfPanel = document.getElementById('review-what-if-panel');
  const whatIfButton = document.getElementById('review-what-if-evaluate');
  const whatIfResult = document.getElementById('review-what-if-result');
  if (whatIfToggle && whatIfPanel) {
    whatIfToggle.addEventListener('change', () => {
      whatIfPanel.hidden = !whatIfToggle.checked;
    });
  }
  if (whatIfButton && whatIfPanel && whatIfResult) {
    whatIfButton.addEventListener('click', async () => {
      const predicateValues = {};
      whatIfPanel.querySelectorAll('[data-predicate-id]').forEach(select => {
        predicateValues[select.dataset.predicateId] = select.value;
      });
      whatIfButton.disabled = true;
      whatIfResult.textContent = 'Evaluating extracted model…';
      try {
        const response = await fetch(`/api/review/${encodeURIComponent(whatIfPanel.dataset.runName)}/decision-evaluate`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({predicate_values: predicateValues}),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
        const outputs = (payload.outputs || []).map(item => `${item.target} = ${item.value_expression || item.effect_kind}`);
        whatIfResult.textContent = [
          `Status: ${payload.status}`,
          `Matched rule: ${payload.matched_rule_id || 'none'}`,
          `Outputs: ${outputs.length ? outputs.join('; ') : 'none'}`,
          `Blockers: ${(payload.blockers || []).join(', ') || 'none'}`,
          `Result digest: ${payload.content_digest}`,
        ].join('\n');
      } catch (error) {
        whatIfResult.textContent = `Evaluation blocked: ${error.message}`;
      } finally {
        whatIfButton.disabled = false;
      }
    });
  }

  applyGroup(body.dataset.selectedGroup || 'decision', false);
  activateTab(body.dataset.selectedTab || 'decision', false);
})();
