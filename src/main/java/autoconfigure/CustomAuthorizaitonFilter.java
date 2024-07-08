package autoconfigure;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class CustomAuthorizaitonFilter extends OncePerRequestFilter {

	List<String> allowedScopes = Arrays.asList(
            "patient/*.read", "patient/AllergyIntolerance.read", "patient/CarePlan.read", 
            "patient/CareTeam.read", "patient/Condition.read", "patient/Device.read", 
            "patient/DiagnosticReport.read", "patient/DocumentReference.read", 
            "patient/Encounter.read", "patient/Goal.read", "patient/Immunization.read", 
            "patient/Location.read", "patient/Medication.read", "patient/MedicationRequest.read", 
            "patient/Observation.read", "patient/Organization.read", "patient/Patient.read", 
            "patient/Practitioner.read", "patient/PractitionerRole.read", "patient/Procedure.read", 
            "patient/Provenance.read", "user/*.read", "user/*.write", "user/AllergyIntolerance.read", 
            "user/CarePlan.read", "user/CareTeam.read", "user/Condition.read", "user/Device.read", 
            "user/DiagnosticReport.read", "user/DocumentReference.read", "user/Encounter.read", 
            "user/Goal.read", "user/Immunization.read", "user/Location.read", "user/Medication.read", 
            "user/MedicationRequest.read", "user/Observation.read", "user/Organization.read", 
            "user/Patient.read", "user/Practitioner.read", "user/PractitionerRole.read", 
            "user/Procedure.read", "user/Provenance.read"
        );
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		System.out.println("custom authorization filter..");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> principal = (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
            AccessToken accessToken = principal.getKeycloakSecurityContext().getToken();

            // Access custom claims
            String fhirScopes = accessToken.getOtherClaims().get("fhirScopes").toString();
			List<String> tokenScopes = Arrays.asList(fhirScopes.split(" "));
			String requiredScope = request.getParameter("scope");
			System.out.println("scopes available in token : " + tokenScopes);
			System.out.println("scope required in url : " + requiredScope);
			if (StringUtils.hasText(requiredScope) && tokenScopes.contains(requiredScope)) {
				if(allowedScopes.contains(requiredScope)) {
					filterChain.doFilter(request, response);
				} else {
					response.setStatus(HttpServletResponse.SC_FORBIDDEN);
					response.getWriter().write("Access Denied. Required scope not found in Allowed Scopes.");
				}
			} else {
				// Access denied
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				response.getWriter().write("Access Denied. Required scope not found in token.");
			}
		} else {
			// No valid authentication found
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getWriter().write("Unauthorized, Token not present");
//			filterChain.doFilter(request, response);

		}
	}

}

