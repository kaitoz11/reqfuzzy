"use strict";
(function () {
  var core = FlowMapCore, initial = JSON.parse(document.getElementById("project-data").textContent);
  var state = { project: core.clone(initial), phase: "flow", index: 0, search: "", location: "", zoom: 1, undo: [], redo: [] };
  var palette = { json: "#43783a", header: "#2864c7", query: "#536f99", path: "#7555b5", form: "#11786c", cookie: "#b75621" };
  var graphWidth = 800, graphHeight = 600;
  function $(id) { return document.getElementById(id); }
  function element(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  function svgElement(tag, attributes, text) {
    var node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.keys(attributes || {}).forEach(function (key) { node.setAttribute(key, String(attributes[key])); });
    if (text !== undefined) node.textContent = String(text);
    return node;
  }
  function phase() { return state.project.flows.find(function (item) { return item.key === state.phase; }); }
  function key() { return state.phase + ":" + state.index; }
  function clip(value, length) { value = String(value || ""); return value.length > length ? value.slice(0, Math.max(0, length - 1)) + "…" : value; }
  function snapshot() { return { project: core.clone(state.project), phase: state.phase, index: state.index }; }
  function remember() { state.undo.push(snapshot()); if (state.undo.length > 50) state.undo.shift(); state.redo = []; }
  function edit(action) { remember(); action(); render(true); revealSelected(); }
  function selectNode(nodeKey, focus) {
    var parts = nodeKey.split(":"), index = Number(parts[1]);
    state.phase = parts[0]; state.index = index;
    render(false);
    revealSelected();
    if (focus) { var node = $("node-" + state.phase + "-" + index); if (node) node.focus(); }
  }
  function button(label, action, className) {
    var node = element("button", label, className || "small"); node.type = "button"; node.addEventListener("click", action); return node;
  }
  function field(parent, label, value, focusKey, change, options) {
    var wrapper = element("label", null, "field"), title = element("span", label), input;
    wrapper.append(title);
    if (options) {
      input = element("select");
      options.forEach(function (option) {
        var item = element("option", typeof option === "string" ? option : option.label);
        item.value = typeof option === "string" ? option : option.value;
        input.append(item);
      });
    } else input = element("input");
    input.value = value === undefined ? "" : String(value);
    input.dataset.focus = focusKey;
    input.addEventListener(options ? "change" : "input", function () { var next = input.value; edit(function () { change(next); }); });
    wrapper.append(input); parent.append(wrapper); return input;
  }
  function section(parent, title, add) {
    var heading = element("div", null, "section-title"); heading.append(element("h3", title));
    if (add) heading.append(button("Add", add)); parent.append(heading);
  }
  function captureFocus() {
    var node = document.activeElement;
    if (!node || !node.dataset.focus) return null;
    return { key: node.dataset.focus, start: node.selectionStart, end: node.selectionEnd };
  }
  function restoreFocus(focus) {
    if (!focus) return;
    var node = document.querySelector('[data-focus="' + focus.key + '"]');
    if (!node) return;
    node.focus({ preventScroll: true });
    if (typeof focus.start === "number" && typeof node.setSelectionRange === "function") node.setSelectionRange(focus.start, focus.end);
  }
  function renderHeader(analysis) {
    $("project-title").textContent = state.project.flows[0].definition.name || "API journey";
    var dirty = JSON.stringify(state.project) !== JSON.stringify(initial);
    $("summary").textContent = analysis.nodes.length + " steps · " + analysis.edges.length + " dependencies · " + (dirty ? "Draft changes" : "Project snapshot");
    $("undo").disabled = !state.undo.length; $("redo").disabled = !state.redo.length; $("reset").disabled = !dirty;
    var filename = phase().file.split(/[\\/]/).pop();
    $("download").textContent = "Export " + filename; $("download").title = "Export " + phase().file;
    $("download").disabled = !analysis.valid;
    $("phases").replaceChildren();
    state.project.flows.forEach(function (item) {
      var tab = button(item.label, function () { selectNode(item.key + ":0", false); }, "");
      tab.setAttribute("aria-pressed", String(item.key === state.phase)); $("phases").append(tab);
    });
    var campaign = $("campaign"); campaign.replaceChildren(); campaign.hidden = !state.project.campaign;
    if (state.project.campaign) {
      var meta = state.project.campaign, content = element("div");
      content.append(element("strong", meta.name), element("p", meta.checks.length + " checks · Campaign references stay fixed in this map", "status"));
      campaign.append(content, element("span", "Target " + meta.target.step + " · " + meta.target.location + ":" + meta.target.path, "badge"));
    }
    $("map-caption").textContent = "Request order by actor · Select a step or dependency to edit";
  }
  function renderProblems(analysis) {
    var panel = $("problems"); panel.replaceChildren(); panel.hidden = analysis.valid;
    if (analysis.valid) return;
    panel.append(element("h2", analysis.errors.length + " issue" + (analysis.errors.length === 1 ? "" : "s") + " to fix before export"));
    var list = element("ul");
    analysis.errors.slice(0, 30).forEach(function (error) {
      var item = element("li");
      if (error.key) item.append(button(error.message, function () { selectNode(error.key, false); }));
      else item.textContent = error.message;
      list.append(item);
    });
    panel.append(list);
  }
  function availableVariables(analysis, nodeKey) {
    var order = new Map(); analysis.nodes.forEach(function (node, index) { order.set(node.key, index); });
    return Array.from(analysis.sources.values()).filter(function (source) { return order.get(source.key) < order.get(nodeKey); }).map(function (source) { return source.name; });
  }
  function renderInspector(analysis) {
    var container = $("inspector"), active = phase(), steps = active.definition.steps;
    container.replaceChildren();
    var head = element("div", null, "inspector-head");
    head.append(element("p", active.label, "eyebrow"), element("h2", steps[state.index] ? steps[state.index].id || "New step" : "No step selected"));
    head.append(element("p", active.file, "status mono")); container.append(head);
    var body = element("div", null, "inspector-body"); container.append(body);
    field(body, "Flow name", active.definition.name, "flow-name", function (value) { active.definition.name = value; });
    var step = steps[state.index];
    if (!step) { body.append(element("p", "Add a step to start this flow.", "help")); return; }
    var prefix = key() + "-";
    var actions = element("div", null, "actions");
    var up = button("Move up", function () { edit(function () { var previous = steps[state.index - 1]; steps[state.index - 1] = step; steps[state.index] = previous; state.index--; }); }); up.disabled = state.index === 0;
    var down = button("Move down", function () { edit(function () { var next = steps[state.index + 1]; steps[state.index + 1] = step; steps[state.index] = next; state.index++; }); }); down.disabled = state.index === steps.length - 1;
    actions.append(up, down, button("Delete step", function () { edit(function () { steps.splice(state.index, 1); state.index = Math.min(state.index, steps.length - 1); }); }, "small danger")); body.append(actions);
    section(body, "Request step");
    field(body, "Step ID", step.id, prefix + "id", function (value) { step.id = value; });
    var requests = [{ value: "", label: "Choose a registered request" }].concat(state.project.requests);
    field(body, "Request", step.request, prefix + "request", function (value) { step.request = value; }, requests);
    var grid = element("div", null, "field-grid"); body.append(grid);
    field(grid, "Actor", step.actor || "", prefix + "actor", function (value) { if (value) step.actor = value; else delete step.actor; });
    field(grid, "Expected HTTP status", step.expect_status, prefix + "status", function (value) { if (value === "") delete step.expect_status; else step.expect_status = /^\d+$/.test(value) ? Number(value) : value; });
    field(body, "Before-send hook", step.before_send, prefix + "before", function (value) { if (value) step.before_send = value; else delete step.before_send; });
    field(body, "After-response hook", step.after_response, prefix + "after", function (value) { if (value) step.after_response = value; else delete step.after_response; });
    section(body, "Response extractions", function () { edit(function () { if (!step.extract) step.extract = []; step.extract.push({ name: "", json: "" }); }); });
    (step.extract || []).forEach(function (extraction, index) {
      var entry = element("div", null, "entry"), row = prefix + "extract-" + index + "-";
      field(entry, "Variable name", extraction.name, row + "name", function (value) { extraction.name = value; });
      var kind = Object.prototype.hasOwnProperty.call(extraction, "cookie") ? "cookie" : "json";
      field(entry, "Source", kind, row + "source", function (value) { var selector = extraction[kind] || ""; delete extraction.json; delete extraction.cookie; extraction[value] = selector; }, [{ value: "json", label: "JSON response" }, { value: "cookie", label: "Set-Cookie response" }]);
      field(entry, kind === "cookie" ? "Cookie name" : "JSON selector", extraction[kind] || "", row + "selector", function (value) { extraction[kind] = value; });
      entry.append(button("Remove extraction", function () { edit(function () { step.extract.splice(index, 1); if (!step.extract.length) delete step.extract; }); }, "small quiet danger")); body.append(entry);
    });
    if (!(step.extract || []).length) body.append(element("p", "Extract a response value for later requests.", "help"));
    section(body, "Hook-provided variables", function () { edit(function () { if (!step.provides) step.provides = []; step.provides.push(""); }); });
    (step.provides || []).forEach(function (name, index) {
      var entry = element("div", null, "entry");
      field(entry, "Provided variable", name, prefix + "provided-" + index, function (value) { step.provides[index] = value; });
      entry.append(button("Remove variable", function () { edit(function () { step.provides.splice(index, 1); if (!step.provides.length) delete step.provides; }); }, "small quiet danger")); body.append(entry);
    });
    var available = availableVariables(analysis, key());
    section(body, "Request bindings", function () { edit(function () { if (!step.bind) step.bind = []; step.bind.push({ location: "json", path: "", variable: available[0] || "" }); }); });
    (step.bind || []).forEach(function (binding, index) {
      var entry = element("div", null, "entry"), row = prefix + "bind-" + index + "-";
      var variables = [{ value: "", label: "Choose an earlier variable" }].concat(available);
      if (binding.variable && available.indexOf(binding.variable) < 0) variables.push({ value: binding.variable, label: binding.variable + " (needs earlier source)" });
      field(entry, "Variable", binding.variable, row + "variable", function (value) { binding.variable = value; }, variables);
      var columns = element("div", null, "field-grid"); entry.append(columns);
      field(columns, "Location", binding.location, row + "location", function (value) { binding.location = value; }, core.locations);
      field(columns, "Address", binding.path, row + "path", function (value) { binding.path = value; });
      field(entry, "Prefix" + (binding.location === "json" ? " (empty for JSON)" : ""), binding.prefix || "", row + "prefix", function (value) { if (value) binding.prefix = value; else delete binding.prefix; });
      var source = analysis.sources.get(binding.variable), info = element("div", null, "entry-foot");
      info.append(element("span", source ? source.selector : "No earlier source"), button("Remove", function () { edit(function () { step.bind.splice(index, 1); if (!step.bind.length) delete step.bind; }); }, "small quiet danger")); entry.append(info); body.append(entry);
    });
    if (!(step.bind || []).length) body.append(element("p", "Bind an earlier variable into this request.", "help"));
    body.append(element("p", "Request files and hook source stay in your project. The CLI checks them before execution.", "help"));
  }
  function renderGraph(analysis) {
    var actors = [], positions = new Map(), portsOut = new Map(), portsIn = new Map();
    analysis.nodes.forEach(function (node) { var actor = node.step.actor || "default"; if (actors.indexOf(actor) < 0) actors.push(actor); portsOut.set(node.key, []); portsIn.set(node.key, []); });
    analysis.edges.forEach(function (edge) { portsOut.get(edge.from).push(edge); portsIn.get(edge.to).push(edge); });
    var y = 72, lastPhase = "";
    analysis.nodes.forEach(function (node) {
      if (node.phase !== lastPhase && lastPhase) y += 32;
      var count = portsOut.get(node.key).length + portsIn.get(node.key).length, height = Math.max(120, 112 + count * 22);
      positions.set(node.key, { x: 48 + actors.indexOf(node.step.actor || "default") * 340, y: y, height: height, node: node });
      y += height + 56; lastPhase = node.phase;
    });
    graphWidth = Math.max(760, actors.length * 340 + 300 + analysis.edges.length * 22); graphHeight = Math.max(400, y + 20);
    var svg = svgElement("svg", { viewBox: "0 0 " + graphWidth + " " + graphHeight, role: "group", "aria-labelledby": "flow-map-title flow-map-desc" });
    svg.append(svgElement("title", { id: "flow-map-title" }, "API journey dependencies"), svgElement("desc", { id: "flow-map-desc" }, "Ordered request steps grouped by actor, with labeled variable dependencies across journey and verification flows."));
    var defs = svgElement("defs");
    ["order"].concat(core.locations).forEach(function (location) {
      var marker = svgElement("marker", { id: "arrow-" + location, viewBox: "0 0 8 8", refX: 7, refY: 4, markerWidth: 7, markerHeight: 7, orient: "auto", markerUnits: "userSpaceOnUse" });
      marker.append(svgElement("path", { d: "M 0 0 L 8 4 L 0 8 Z", fill: palette[location] || "#aab6c7" })); defs.append(marker);
    }); svg.append(defs);
    actors.forEach(function (actor, index) { svg.append(svgElement("text", { x: 56 + index * 340, y: 24, "class": "lane" }, "actor · " + clip(actor, 35))); });
    analysis.nodes.forEach(function (node, index) {
      var position = positions.get(node.key), previous = index > 0 ? positions.get(analysis.nodes[index - 1].key) : null;
      if (previous) {
        var x1 = previous.x + 143, y1 = previous.y + previous.height, x2 = position.x + 143, y2 = position.y, mid = (y1 + y2) / 2, direction = x2 > x1 ? 1 : -1;
        var path = x1 === x2 ? "M " + x1 + " " + y1 + " V " + y2 : "M " + x1 + " " + y1 + " V " + (mid - 8) + " Q " + x1 + " " + mid + " " + (x1 + direction * 8) + " " + mid + " H " + (x2 - direction * 8) + " Q " + x2 + " " + mid + " " + x2 + " " + (mid + 8) + " V " + y2;
        svg.append(svgElement("path", { d: path, fill: "none", stroke: "#aab6c7", "stroke-width": 1.2, "marker-end": "url(#arrow-order)", "stroke-dasharray": node.phase !== analysis.nodes[index - 1].phase ? "4 4" : "none" }));
      }
      if (index === 0 || node.phase !== analysis.nodes[index - 1].phase) svg.append(svgElement("text", { x: 48, y: position.y - 24, "class": "lane" }, node.label));
    });
    var query = state.search.toLowerCase(), selected = key();
    analysis.edges.forEach(function (edge, edgeIndex) {
      var from = positions.get(edge.from), to = positions.get(edge.to), sourcePort = portsOut.get(edge.from).indexOf(edge), targetPort = portsIn.get(edge.to).indexOf(edge);
      var x1 = from.x + 286, y1 = from.y + 102 + (portsIn.get(edge.from).length + sourcePort) * 22, x2 = to.x + 286, y2 = to.y + 102 + targetPort * 22;
      var track = actors.length * 340 + 260 + edgeIndex * 22, color = palette[edge.location] || "#536f99";
      var match = (!state.location || edge.location === state.location) && (!query || (edge.variable + " " + edge.location + " " + edge.path).toLowerCase().indexOf(query) >= 0);
      var connected = edge.from === selected || edge.to === selected;
      var group = svgElement("g", { "class": "edge", tabindex: 0, role: "button", "aria-label": "Edit " + edge.variable + " binding at " + edge.location + ":" + edge.path, opacity: match ? (connected ? 1 : .6) : .1 });
      group.append(svgElement("path", { d: "M " + x1 + " " + y1 + " H " + (track - 8) + " Q " + track + " " + y1 + " " + track + " " + (y1 + 8) + " V " + (y2 - 8) + " Q " + track + " " + y2 + " " + (track - 8) + " " + y2 + " H " + x2, stroke: color, "marker-end": "url(#arrow-" + edge.location + ")" }));
      var label = clip(edge.variable + " · " + edge.location + ":" + edge.path, Math.max(12, Math.min(44, Math.floor((track - x1 - 32) / 6))));
      group.append(svgElement("rect", { x: x1 + 10, y: y1 - 20, width: label.length * 6.1 + 8, height: 16, rx: 3, "class": "edge-label" }), svgElement("text", { x: x1 + 14, y: y1 - 8, fill: color }, label));
      function activate() { selectNode(edge.to, false); var control = document.querySelector('[data-focus="' + edge.to + "-bind-" + edge.bindingIndex + '-path"]'); if (control) control.focus({ preventScroll: false }); }
      group.addEventListener("click", activate); group.addEventListener("keydown", function (event) { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); activate(); } }); svg.append(group);
    });
    var errors = new Set(analysis.errors.map(function (error) { return error.key; }));
    analysis.nodes.forEach(function (node, index) {
      var position = positions.get(node.key), step = node.step, actor = step.actor || "default";
      var matches = !query || (step.id + " " + step.request + " " + actor + " " + JSON.stringify(step.bind || []) + " " + JSON.stringify(step.extract || [])).toLowerCase().indexOf(query) >= 0;
      var group = svgElement("g", { id: "node-" + node.phase + "-" + node.index, "class": "node" + (node.key === selected ? " selected" : "") + (errors.has(node.key) ? " error-node" : ""), tabindex: 0, role: "button", "aria-label": "Select " + node.label + " step " + (step.id || "unnamed"), opacity: matches ? 1 : .35 });
      group.append(svgElement("rect", { x: position.x, y: position.y, width: 286, height: position.height, rx: 8, "class": "frame" }));
      var target = state.project.campaign && node.phase === "flow" && step.id === state.project.campaign.target.step;
      if (target) group.append(svgElement("rect", { x: position.x, y: position.y + 8, width: 4, height: position.height - 16, rx: 2, style: "fill:#b75621;stroke:none" }));
      group.append(svgElement("text", { x: position.x + 16, y: position.y + 24, "class": "sub" }, String(index + 1).padStart(2, "0") + " / " + node.label + (target ? " · TARGET" : "")));
      group.append(svgElement("text", { x: position.x + 16, y: position.y + 48, "class": "title" }, clip(step.id || "Unnamed step", 32)));
      group.append(svgElement("text", { x: position.x + 16, y: position.y + 70, "class": "sub" }, "request · " + clip(step.request, 31)));
      var hooks = [step.before_send, step.after_response].filter(Boolean);
      group.append(svgElement("text", { x: position.x + 16, y: position.y + 89, "class": "meta" }, (step.expect_status ? "HTTP " + step.expect_status + " · " : "") + ((step.extract || []).length + (step.provides || []).length) + " variables" + (hooks.length ? " · " + hooks.length + " hooks" : "")));
      group.addEventListener("click", function () { selectNode(node.key, false); });
      group.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(node.key, true); }
        if (event.key === "ArrowDown" && analysis.nodes[index + 1]) { event.preventDefault(); selectNode(analysis.nodes[index + 1].key, true); }
        if (event.key === "ArrowUp" && analysis.nodes[index - 1]) { event.preventDefault(); selectNode(analysis.nodes[index - 1].key, true); }
      }); svg.append(group);
    });
    $("canvas").replaceChildren(svg); applyZoom();
    var legend = $("legend"); legend.replaceChildren();
    var order = element("span", "Request order"); var stroke = element("i", null, "swatch"); order.prepend(stroke); legend.append(order);
    core.locations.forEach(function (location) { if (!analysis.edges.some(function (edge) { return edge.location === location; })) return; var item = element("span", location); item.style.color = palette[location]; item.prepend(element("i", null, "swatch")); legend.append(item); });
  }
  function applyZoom() {
    var svg = $("canvas").querySelector("svg");
    if (svg) { svg.style.width = Math.round(graphWidth * state.zoom) + "px"; svg.style.height = Math.round(graphHeight * state.zoom) + "px"; }
    $("zoom-label").textContent = Math.round(state.zoom * 100) + "%";
  }
  function revealSelected() {
    var node = $("node-" + state.phase + "-" + state.index), canvas = $("canvas");
    if (!node) return;
    var box = node.getBoundingClientRect(), viewport = canvas.getBoundingClientRect();
    if (box.top < viewport.top + 16) canvas.scrollTop -= viewport.top + 16 - box.top;
    else if (box.bottom > viewport.bottom - 16) canvas.scrollTop += box.bottom - viewport.bottom + 16;
    if (box.left < viewport.left + 16) canvas.scrollLeft -= viewport.left + 16 - box.left;
    else if (box.right > viewport.right - 16) canvas.scrollLeft += box.right - viewport.right + 16;
  }
  function render(keepFocus) {
    var focus = keepFocus ? captureFocus() : null, analysis = core.analyze(state.project);
    renderHeader(analysis); renderProblems(analysis); renderGraph(analysis); renderInspector(analysis); restoreFocus(focus);
  }
  $("search").addEventListener("input", function () { state.search = this.value; render(false); });
  $("location").addEventListener("change", function () { state.location = this.value; render(false); });
  $("add-step").addEventListener("click", function () { edit(function () { var active = phase(); active.definition.steps.push(core.newStep(state.project, state.phase)); state.index = active.definition.steps.length - 1; }); });
  $("undo").addEventListener("click", function () { if (!state.undo.length) return; state.redo.push(snapshot()); var previous = state.undo.pop(); state.project = previous.project; state.phase = previous.phase; state.index = previous.index; render(false); });
  $("redo").addEventListener("click", function () { if (!state.redo.length) return; state.undo.push(snapshot()); var next = state.redo.pop(); state.project = next.project; state.phase = next.phase; state.index = next.index; render(false); });
  $("reset").addEventListener("click", function () { remember(); state.project = core.clone(initial); state.phase = "flow"; state.index = 0; render(false); });
  $("zoom-in").addEventListener("click", function () { state.zoom = Math.min(2, state.zoom + .1); applyZoom(); });
  $("zoom-out").addEventListener("click", function () { state.zoom = Math.max(.25, state.zoom - .1); applyZoom(); });
  $("fit").addEventListener("click", function () { state.zoom = Math.max(.1, Math.min(1, ($("canvas").clientWidth - 12) / graphWidth)); applyZoom(); });
  $("download").addEventListener("click", function () {
    var content = core.exportFlow(state.project, state.phase), blob = new Blob([content], { type: "application/yaml;charset=utf-8" });
    var url = URL.createObjectURL(blob), link = element("a"); link.href = url; link.download = phase().file.split(/[\\/]/).pop(); document.body.append(link); link.click(); link.remove(); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });
  render(false);
})();
