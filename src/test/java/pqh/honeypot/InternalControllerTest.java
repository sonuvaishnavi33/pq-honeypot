package pqh.honeypot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import pqh.crypto.Ev;

class InternalControllerTest {
  @Test
  void customSimulationRecordsValidatedInputAsOneEvent() {
    EventService events = mock(EventService.class);
    Ev expected = new Ev(12, "2026-11-17T00:00:00Z", "203.0.113.42", null,
        "/login", "POST", "dashboard-simulator/1.0", 30, "MEDIUM", "R5");
    when(events.record("203.0.113.42", null, null, "/login", "POST",
        "dashboard-simulator/1.0", "probe=sample", true)).thenReturn(expected);
    InternalController controller = controller(events, true);

    Ev result = controller.simulateCustom(new InternalController.CustomSimulationRequest(
        "203.0.113.42", " ", "/login", "post", "dashboard-simulator/1.0", "probe=sample", true));

    assertEquals(expected, result);
    verify(events).record("203.0.113.42", null, null, "/login", "POST",
        "dashboard-simulator/1.0", "probe=sample", true);
  }

  @Test
  void customSimulationRejectsInvalidEndpointAndNonDemoMode() {
    EventService events = mock(EventService.class);
    InternalController demoController = controller(events, true);
    ResponseStatusException invalidEndpoint = assertThrows(ResponseStatusException.class, () ->
        demoController.simulateCustom(new InternalController.CustomSimulationRequest(
            "203.0.113.42", null, "https://example.test", "GET", null, null, false)));
    assertEquals(HttpStatus.BAD_REQUEST, invalidEndpoint.getStatusCode());

    ResponseStatusException invalidIp = assertThrows(ResponseStatusException.class, () ->
        demoController.simulateCustom(new InternalController.CustomSimulationRequest(
            "999.1.1.1", null, "/login", "GET", null, null, false)));
    assertEquals(HttpStatus.BAD_REQUEST, invalidIp.getStatusCode());

    ResponseStatusException disabledDemo = assertThrows(ResponseStatusException.class, () ->
        controller(events, false).simulateCustom(new InternalController.CustomSimulationRequest(
            "203.0.113.42", null, "/login", "GET", null, null, false)));
    assertEquals(HttpStatus.FORBIDDEN, disabledDemo.getStatusCode());
    verifyNoInteractions(events);
  }

  private InternalController controller(EventService events, boolean demo) {
    return new InternalController(events, mock(ForwardService.class), mock(SelfTestService.class), demo);
  }
}
