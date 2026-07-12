package com.eitanroni.miniwsa.api.jackson;

import com.eitanroni.miniwsa.api.dto.EventIngestionRequest;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class EventIngestionRequestDeserializer extends JsonDeserializer<EventIngestionRequest> {

    @Override
    public EventIngestionRequest deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);

        if (root == null || root.isNull()) {
            throw new JsonMappingException(parser, "Request body must be a security event object or a JSON array of security events");
        }

        List<SecurityEventRequest> events;
        if (root.isArray()) {
            events = new ArrayList<>();
            for (JsonNode eventNode : root) {
                events.add(mapper.treeToValue(eventNode, SecurityEventRequest.class));
            }
        } else if (root.isObject()) {
            events = List.of(mapper.treeToValue(root, SecurityEventRequest.class));
        } else {
            throw new JsonMappingException(parser, "Request body must be a security event object or a JSON array of security events");
        }

        return new EventIngestionRequest(events);
    }
}
