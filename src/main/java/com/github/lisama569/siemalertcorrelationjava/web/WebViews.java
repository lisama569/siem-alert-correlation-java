package com.github.lisama569.siemalertcorrelationjava.web;

import com.github.lisama569.siemalertcorrelationjava.alert.Alert;
import com.github.lisama569.siemalertcorrelationjava.ingest.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.model.IngestResult;
import com.github.lisama569.siemalertcorrelationjava.web.dto.AlertView;
import com.github.lisama569.siemalertcorrelationjava.web.dto.DispositionView;
import com.github.lisama569.siemalertcorrelationjava.web.dto.EventRequest;
import com.github.lisama569.siemalertcorrelationjava.web.dto.ItemResult;

import java.util.Map;

/** 领域对象 ↔ HTTP 视图的纯函数映射（无副作用）。 */
final class WebViews {

    private WebViews() {
    }

    static RawEvent toRaw(EventRequest r) {
        return new RawEvent(r.eventId(), r.source(), r.type(), r.occurredAt(),
                r.attributes() == null ? Map.of() : r.attributes());
    }

    static ItemResult item(EventRequest req, IngestResult result) {
        String submittedId = req.eventId();
        if (result instanceof IngestResult.Accepted a) {
            return new ItemResult("ACCEPTED", a.event().eventId(), null, "事件已受理");
        }
        if (result instanceof IngestResult.Duplicate d) {
            return new ItemResult("DUPLICATE", d.eventId(), null,
                    "重复提交，未重复计数或告警");
        }
        IngestResult.Rejected r = (IngestResult.Rejected) result;
        return new ItemResult("REJECTED", submittedId, r.reason().name(), r.detail());
    }

    static AlertView alertView(Alert a) {
        return new AlertView(
                a.getAlertId(),
                a.getRuleId(),
                a.getRuleVersion(),
                a.getTitle(),
                a.getSeverity(),
                a.getStatus().name(),
                a.getVersion(),
                a.getCreatedAt().toString(),
                a.getEventIds(),
                a.getEnrichment(),
                a.getHistory().stream()
                        .map(h -> new DispositionView(
                                h.at().toString(), h.operator(), h.action(),
                                h.from().name(), h.to().name(), h.note()))
                        .toList());
    }
}
