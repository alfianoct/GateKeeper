package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/models"
)

type contextKey string

const (
	ctxUser           contextKey = "user"
	ctxEffPerms       contextKey = "effective_permissions"
	sessionCookieName            = "gk_session"
)

func UserFromContext(ctx context.Context) *models.User {
	u, _ := ctx.Value(ctxUser).(*models.User)
	return u
}

// Validates gk_session cookie, injects user into context, 401 if missing/invalid.
func AuthMiddleware(sessions *auth.SessionStore, users *models.UserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""

			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				token = cookie.Value
			}

			// fallback to Bearer token — careful, tokens can leak in logs/proxies
			if token == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					token = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if token == "" {
				jsonError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := sessions.Validate(token)
			if err != nil {
				http.SetCookie(w, &http.Cookie{
					Name:     sessionCookieName,
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
				})
				jsonError(w, http.StatusUnauthorized, "session invalid or expired")
				return
			}

			user, err := users.GetByID(userID)
			if err != nil {
				jsonError(w, http.StatusUnauthorized, "user not found")
				return
			}

			if user.Disabled {
				jsonError(w, http.StatusForbidden, "account disabled")
				return
			}

			ctx := context.WithValue(r.Context(), ctxUser, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Platform-admins always pass; everyone else needs the permission via groups.
func RequirePermission(groups *models.GroupStore, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				jsonError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			if user.Role == "platform-admin" {
				next.ServeHTTP(w, r)
				return
			}

			userGroups := splitGroups(user.Groups)
			has, err := groups.HasPermission(userGroups, permission)
			if err != nil || !has {
				jsonError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Health/readiness endpoints are exempted so load balancers don't get locked out.
func GlobalIPFilter(ipRules *models.IPRuleStore, auditStore *models.AuditStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == "/ready" {
				next.ServeHTTP(w, r)
				return
			}
			allowed, reason := ipRules.Check(r.RemoteAddr, "global", "")
			if !allowed {
				slog.Warn("global IP filter blocked request", "ip", r.RemoteAddr, "reason", reason)
				auditStore.Log(&models.AuditEntry{
					Action:   "ip_blocked",
					Username: "anonymous",
					Detail:   reason,
					SourceIP: r.RemoteAddr,
				})
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func splitGroups(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
