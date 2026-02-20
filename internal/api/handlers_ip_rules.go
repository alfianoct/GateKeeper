package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/models"
)

type IPRuleHandler struct {
	IPRules *models.IPRuleStore
	Audit   *models.AuditStore
}

func (h *IPRuleHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.IPRules.List()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list IP rules")
		return
	}
	if rules == nil {
		rules = []models.IPRule{}
	}
	jsonResponse(w, http.StatusOK, rules)
}

func (h *IPRuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())

	var rule models.IPRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if rule.RuleType != "allow" && rule.RuleType != "deny" {
		jsonError(w, http.StatusBadRequest, "rule_type must be 'allow' or 'deny'")
		return
	}
	if rule.CIDR == "" {
		jsonError(w, http.StatusBadRequest, "cidr is required")
		return
	}
	if rule.Scope == "" {
		rule.Scope = "global"
	}
	if rule.Scope != "global" && rule.Scope != "host" {
		jsonError(w, http.StatusBadRequest, "scope must be 'global' or 'host'")
		return
	}
	if rule.Scope == "host" && rule.ScopeID == "" {
		jsonError(w, http.StatusBadRequest, "scope_id is required when scope is 'host'")
		return
	}

	if user != nil {
		rule.CreatedBy = user.Username
	}

	if err := h.IPRules.Create(&rule); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "ip_rule_created",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   rule.RuleType + " " + rule.CIDR + " scope=" + rule.Scope,
		SourceIP: r.RemoteAddr,
	})

	jsonResponse(w, http.StatusCreated, rule)
}

func (h *IPRuleHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	ruleID := chi.URLParam(r, "id")

	if err := h.IPRules.Delete(ruleID); err != nil {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "ip_rule_deleted",
		UserID:   user.ID,
		Username: user.Username,
		TargetID: ruleID,
		Detail:   "IP rule deleted",
		SourceIP: r.RemoteAddr,
	})

	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}
