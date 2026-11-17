package pqh.honeypot;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pqh.crypto.*;

@Service @Profile("honeypot")
public class EventService {
  private final JdbcTemplate db; private final RulesEngine rules; private final EpochIntegrityService integrity; private final String node;
  public EventService(JdbcTemplate db, RulesEngine rules, EpochIntegrityService integrity, @Value("${app.node-id}") String node) {
    this.db = db; this.rules = rules; this.integrity = integrity; this.node = node;
  }

  @Transactional
  public synchronized Ev record(String ip, String user, String pass, String endpoint, String method, String ua, String payload, boolean failedLogin) {
    var r = rules.evaluate(ip, user, pass, endpoint, ua, payload, failedLogin, System.currentTimeMillis());
    long seq = db.queryForObject("SELECT COALESCE(MAX(seq_no),0)+1 FROM security_event", Long.class);
    String prev = seq == 1 ? HashChain.genesis(node) : db.queryForObject("SELECT chain_hash FROM security_event WHERE seq_no=?", String.class, seq - 1);
    Ev e = new Ev(seq, Instant.now().toString(), ip, user, endpoint, method, ua, r.score(), r.level(), String.join(",", r.hits()));
    String h = HashChain.next(prev, seq, e.canonical());
    db.update("INSERT INTO security_event(seq_no,event_time,source_ip,username,endpoint,http_method,user_agent,risk_score,risk_level,rules_hit,prev_hash,chain_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        seq, e.time(), ip, user, endpoint, method, ua, e.score(), e.level(), e.rules(), prev, h);
    integrity.eventRecorded();
    return e;
  }
  public List<Ev.Rec> pending(int limit) {
    return db.query("SELECT * FROM security_event WHERE sent_status='PENDING' AND seq_no<=? "
        + "ORDER BY seq_no LIMIT ?", (rs, i) -> new Ev.Rec(new Ev(rs.getLong("seq_no"), rs.getString("event_time"), rs.getString("source_ip"),
        rs.getString("username"), rs.getString("endpoint"), rs.getString("http_method"), rs.getString("user_agent"), rs.getInt("risk_score"), rs.getString("risk_level"), rs.getString("rules_hit")), rs.getString("chain_hash")),
        integrity.forwardableThroughSequence(), limit);
  }
  public void markSent(long first, long last) { db.update("UPDATE security_event SET sent_status='SENT' WHERE seq_no BETWEEN ? AND ?", first, last); }
  public List<java.util.Map<String, Object>> recent(int n) { return db.queryForList("SELECT seq_no,event_time,source_ip,username,endpoint,risk_score,risk_level,rules_hit,sent_status FROM security_event ORDER BY seq_no DESC LIMIT ?", n); }
  public java.util.Map<String, Object> stats() {
    return java.util.Map.of("total", db.queryForObject("SELECT COUNT(*) FROM security_event", Long.class),
        "byLevel", db.queryForList("SELECT risk_level lvl, COUNT(*) n FROM security_event GROUP BY risk_level"),
        "pending", db.queryForObject("SELECT COUNT(*) FROM security_event WHERE sent_status='PENDING'", Long.class),
        "unsealed", integrity.unsealedCount());
  }
  public void tamperOne() { db.update("UPDATE security_event SET username='TAMPERED' WHERE sent_status='PENDING' ORDER BY seq_no DESC LIMIT 1"); }
  @Transactional
  public void reset() { db.update("DELETE FROM security_event"); integrity.reset(); }
}
