package pqh.honeypot;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

/** Fake endpoints: every request is logged and always fails plausibly. */
@RestController @Profile("honeypot")
public class DecoyController {
  private final EventService events;
  public DecoyController(EventService e) { events = e; }

  @RequestMapping({"/login", "/admin/login", "/wp-login.php", "/api/v1/auth"})
  public ResponseEntity<String> login(HttpServletRequest r, @RequestParam(required = false) String username, @RequestParam(required = false) String password) {
    events.record(r.getRemoteAddr(), username, password, r.getRequestURI(), r.getMethod(), r.getHeader("User-Agent"), r.getQueryString(), true);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
  }
  @GetMapping({"/admin", "/.env", "/phpmyadmin", "/.git/config"})
  public ResponseEntity<String> probe(HttpServletRequest r) {
    events.record(r.getRemoteAddr(), null, null, r.getRequestURI(), r.getMethod(), r.getHeader("User-Agent"), r.getQueryString(), false);
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Forbidden");
  }
}
