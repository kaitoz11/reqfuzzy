"use strict";
var FlowMapCore = (function () {
  var locations = ["json", "header", "query", "path", "form", "cookie"];
  var cookieName = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  function clone(value) { return JSON.parse(JSON.stringify(value)); }
  function text(value) { return typeof value === "string"; }
  function filled(value) { return text(value) && value.trim().length > 0; }
  function list(value) { return Array.isArray(value) ? value : []; }
  function analyze(project) {
    var nodes = [], edges = [], controls = [], errors = [], sources = new Map(), phaseSteps = new Map(), requestBound = 0;
    var requests = new Set(list(project.requests));
    function error(key, message) { errors.push({ key: key || "", message: message }); }
    list(project.flows).forEach(function (phase) {
      var definition = phase.definition || {}, ids = new Set(), steps = list(definition.steps);
      phaseSteps.set(phase.key, ids);
      if (!filled(definition.name)) error("", phase.label + ": flow name is required");
      if (!steps.length) error("", phase.label + ": add at least one step");
      steps.forEach(function (step, index) {
        var key = phase.key + ":" + index;
        var node = { key: key, phase: phase.key, index: index, step: step, label: phase.label };
        nodes.push(node);
        var label = phase.label + " / " + (step.id || "step " + (index + 1));
        if (!filled(step.id)) error(key, label + ": step ID is required");
        if (ids.has(step.id)) error(key, label + ": duplicate step ID");
        ids.add(step.id);
        if (!requests.has(step.request)) error(key, label + ": choose a registered request");
        if (step.actor !== undefined && !text(step.actor)) error(key, label + ": actor must be text");
        if (step.expect_status !== undefined && (typeof step.expect_status !== "number" || !Number.isInteger(step.expect_status) || step.expect_status < 100 || step.expect_status > 599)) error(key, label + ": expected status must be an integer from 100 to 599");
        function statuses(value, name) {
          if (!Array.isArray(value) || !value.length || value.some(function (status) { return !Number.isInteger(status) || status < 100 || status > 599; }) || new Set(value).size !== value.length) error(key, label + ": " + name + " needs unique HTTP codes");
        }
        if (step.expect_statuses !== undefined) { statuses(step.expect_statuses, "Expected statuses"); if (step.expect_status !== undefined) error(key, label + ": choose one status or a status set"); }
        var limit = step.max_visits === undefined ? 1 : step.max_visits;
        if (!Number.isInteger(limit) || limit < 1 || limit > 1000000) error(key, label + ": max visits must be 1 through 1000000");
        else requestBound += limit;
        ["before_send", "after_response"].forEach(function (field) { if (step[field] !== undefined && !text(step[field])) error(key, label + ": hook names must be text"); });
        if (step.bind !== undefined && !Array.isArray(step.bind)) error(key, label + ": bindings must be a list");
        list(step.bind).forEach(function (binding, bindingIndex) {
          if (locations.indexOf(binding.location) < 0) error(key, label + ": unsupported binding location");
          if (!text(binding.path) || !binding.path.length) error(key, label + ": binding address is required");
          if (!filled(binding.variable) || !sources.has(binding.variable)) error(key, label + ": variable " + (binding.variable || "(empty)") + " needs an earlier source");
          if (binding.prefix !== undefined && !text(binding.prefix)) error(key, label + ": binding prefix must be text");
          if (binding.location === "json" && binding.prefix) error(key, label + ": JSON bindings cannot use a prefix");
          if (binding.location === "path" && (!/^(0|[1-9][0-9]*)$/.test(binding.path) || !Number.isSafeInteger(Number(binding.path)))) error(key, label + ": path address must be a nonnegative segment index");
          if (binding.location === "cookie" && !cookieName.test(binding.path || "")) error(key, label + ": invalid cookie name");
          if (sources.has(binding.variable)) edges.push({ from: sources.get(binding.variable).key, to: key, variable: binding.variable, location: binding.location, path: binding.path, bindingIndex: bindingIndex });
        });
        function declare(name, selector) {
          if (!filled(name)) { error(key, label + ": variable name is required"); return; }
          if (sources.has(name)) { error(key, label + ": duplicate variable " + name); return; }
          sources.set(name, { key: key, phase: phase.key, index: index, selector: selector, name: name });
        }
        if (step.extract !== undefined && !Array.isArray(step.extract)) error(key, label + ": extractions must be a list");
        list(step.extract).forEach(function (extraction) {
          var json = text(extraction.json) && extraction.json.length > 0, cookie = text(extraction.cookie) && extraction.cookie.length > 0;
          if (json === cookie) error(key, label + ": extraction needs exactly one JSON or cookie selector");
          if (cookie && !cookieName.test(extraction.cookie)) error(key, label + ": invalid response cookie name");
          if (extraction.optional !== undefined && typeof extraction.optional !== "boolean") error(key, label + ": optional must be true or false");
          if (extraction.on_status !== undefined) statuses(extraction.on_status, "Extraction status gate");
          declare(extraction.name, cookie ? "cookie:" + extraction.cookie : "json:" + (extraction.json || ""));
        });
        if (step.provides !== undefined && !Array.isArray(step.provides)) error(key, label + ": provided variables must be a list");
        if (list(step.provides).length && !step.after_response) error(key, label + ": provided variables need an after-response hook");
        list(step.provides).forEach(function (name) { declare(name, "after_response"); });
      });
    });
    list(project.flows).forEach(function (phase) {
      var steps = list(phase.definition.steps), ids = new Map();
      steps.forEach(function (step, index) { ids.set(step.id, phase.key + ":" + index); });
      steps.forEach(function (step, index) {
        var key = phase.key + ":" + index;
        function connect(target, kind, routeIndex) {
          if (!text(target) || (target !== "" && !ids.has(target))) { error(key, phase.label + " / " + step.id + ": next destination does not exist"); return; }
          controls.push({ from: key, to: target === "" ? "" : ids.get(target), target: target, kind: kind, routeIndex: routeIndex });
        }
        if (Object.prototype.hasOwnProperty.call(step, "next")) connect(step.next, "next");
        else connect(index + 1 < steps.length ? steps[index + 1].id : "", "order");
        if (step.routes !== undefined && !Array.isArray(step.routes)) error(key, phase.label + " / " + step.id + ": routes must be a list");
        var seen = new Set();
        list(step.routes).forEach(function (target, routeIndex) { if (seen.has(target)) error(key, phase.label + " / " + step.id + ": duplicate route"); seen.add(target); connect(target, "route", routeIndex); });
      });
    });
    var verification = list(project.flows).find(function (phase) { return phase.key === "verify" && list(phase.definition.steps).length; });
    if (verification) controls.forEach(function (control) { if (!control.to && control.from.indexOf("flow:") === 0) { control.to = "verify:0"; control.via = control.kind; control.kind = "verify"; } });
    if (project.campaign) {
      var campaign = project.campaign, target = campaign.target || {}, main = phaseSteps.get("flow") || new Set();
      if (!main.has(target.step)) error("", "Campaign target step " + target.step + " must remain in the journey");
      var targetNode=nodes.find(function(node){return node.phase==="flow"&&node.step.id===target.step;});
      list(campaign.payload_variables).forEach(function(name){var source=sources.get(name);if(!source||!targetNode||source.phase!=="flow"||source.index>=targetNode.index)error("","Payload variable "+name+" needs a source before the target");});
      list(campaign.checks).forEach(function (check) {
        var phase = check.phase || "flow", ids = phaseSteps.get(phase) || new Set();
        if (!ids.has(check.step)) error("", "Campaign check " + check.id + " refers to missing " + phase + " step " + check.step);
        if (check.variable && !sources.has(check.variable)) error("", "Campaign check " + check.id + " refers to missing variable " + check.variable);
      });
    }
    return { nodes: nodes, edges: edges, controls: controls, requestBound: requestBound, errors: errors, sources: sources, valid: errors.length === 0 };
  }
  function exportFlow(project, key) {
    var analysis = analyze(project);
    if (!analysis.valid) throw new Error("Fix validation issues before exporting");
    var phase = list(project.flows).find(function (item) { return item.key === key; });
    if (!phase) throw new Error("Unknown flow");
    // JSON is valid YAML; escape YAML line-break characters to preserve their
    // exact string values, and markup so an unusual filename cannot execute it.
    return JSON.stringify(phase.definition, null, 2).replace(/[<>&\u0085\u2028\u2029]/g, function (character) {
      return "\\u" + ("0000" + character.charCodeAt(0).toString(16)).slice(-4);
    }) + "\n";
  }
  function newStep(project, phaseKey) {
    var phase = list(project.flows).find(function (item) { return item.key === phaseKey; });
    if (!phase) throw new Error("Unknown flow");
    var used = new Set(list(phase.definition.steps).map(function (step) { return step.id; }));
    var i = 1; while (used.has("step_" + i)) i++;
    return { id: "step_" + i, request: list(project.requests)[0] || "", actor: "default" };
  }
  return { clone: clone, analyze: analyze, exportFlow: exportFlow, newStep: newStep, locations: locations.slice() };
})();
