// pulls in the html partials and jams them into the dom.
// everything loads in parallel so its not *that* slow
const manifest = [
    { name: 'auth',      target: 'before:app-shell' },
    { name: 'dashboard', target: 'main-views' },
    { name: 'hosts',     target: 'main-views' },
    { name: 'terminal',  target: 'main-views' },
    { name: 'security',  target: 'main-views' },
    { name: 'sessions',  target: 'main-views' },
    { name: 'audit',     target: 'main-views' },
    { name: 'access',    target: 'main-views' },
    { name: 'settings',  target: 'main-views' },
    { name: 'modals',    target: 'modal-mount' },
];

async function grab(name) {
    const r = await fetch(`partials/${name}.html`);
    if (!r.ok) throw new Error(`partial ${name} failed: ${r.status}`);
    return { name, html: await r.text() };
}

export async function loadPartials() {
    const results = await Promise.all(manifest.map(m => grab(m.name)));

    const map = {};
    results.forEach(r => map[r.name] = r.html);

    for (const entry of manifest) {
        const html = map[entry.name];
        if (!html) continue;

        if (entry.target.startsWith('before:')) {
            const ref = document.getElementById(entry.target.slice(7));
            if (ref) ref.insertAdjacentHTML('beforebegin', html);
        } else {
            const container = document.getElementById(entry.target);
            if (container) container.insertAdjacentHTML('beforeend', html);
        }
    }
}
