package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.StatsSummaryResponse;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import com.eitanroni.miniwsa.persistence.repository.projection.ActionStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.CategoryStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.ClientIpStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.PathStatsProjection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StatsServiceImplTest {

    private static final Instant FROM = Instant.parse("2026-07-01T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-07-02T00:00:00Z");
    private static final PageRequest TOP_10 = PageRequest.of(0, 10);

    @Mock
    private SecurityEventRepository repository;

    private StatsServiceImpl service() {
        return new StatsServiceImpl(repository);
    }

    private CategoryStatsProjection categoryProjection(RuleCategory category, long count, Double avg) {
        CategoryStatsProjection projection = mock(CategoryStatsProjection.class);
        when(projection.getCategory()).thenReturn(category);
        when(projection.getCount()).thenReturn(count);
        when(projection.getAvgThreatScore()).thenReturn(avg);
        return projection;
    }

    private ActionStatsProjection actionProjection(Action action, long count) {
        ActionStatsProjection projection = mock(ActionStatsProjection.class);
        when(projection.getAction()).thenReturn(action);
        when(projection.getCount()).thenReturn(count);
        return projection;
    }

    private ClientIpStatsProjection attackerProjection(String clientIp, long count, Double avg) {
        ClientIpStatsProjection projection = mock(ClientIpStatsProjection.class);
        when(projection.getClientIp()).thenReturn(clientIp);
        when(projection.getCount()).thenReturn(count);
        when(projection.getAvgThreatScore()).thenReturn(avg);
        return projection;
    }

    private PathStatsProjection pathProjection(String path, long count) {
        PathStatsProjection projection = mock(PathStatsProjection.class);
        when(projection.getPath()).thenReturn(path);
        when(projection.getCount()).thenReturn(count);
        return projection;
    }

    @Test
    void assemblesEveryResponseSectionFromRepositoryProjections() {
        List<CategoryStatsProjection> categoryProjections =
                List.of(categoryProjection(RuleCategory.INJECTION, 450L, 72.34));
        List<ActionStatsProjection> actionProjections =
                List.of(actionProjection(Action.DENY, 890L));
        List<ClientIpStatsProjection> attackerProjections =
                List.of(attackerProjection("203.0.113.42", 87L, 81.23));
        List<PathStatsProjection> pathProjections =
                List.of(pathProjection("/api/v1/login", 234L));

        when(repository.countByReceivedAtRange(14227L, FROM, TO)).thenReturn(1523L);
        when(repository.aggregateByCategory(14227L, FROM, TO)).thenReturn(categoryProjections);
        when(repository.aggregateByAction(14227L, FROM, TO)).thenReturn(actionProjections);
        when(repository.findTopAttackers(eq(14227L), eq(FROM), eq(TO), eq(TOP_10))).thenReturn(attackerProjections);
        when(repository.findTopTargetedPaths(eq(14227L), eq(FROM), eq(TO), eq(TOP_10))).thenReturn(pathProjections);

        StatsSummaryResponse response = service().getSummary(14227L, FROM, TO);

        assertThat(response.configId()).isEqualTo(14227L);
        assertThat(response.timeRange().from()).isEqualTo(FROM);
        assertThat(response.timeRange().to()).isEqualTo(TO);
        assertThat(response.totalEvents()).isEqualTo(1523L);

        assertThat(response.byCategory()).hasSize(1);
        assertThat(response.byCategory().get(RuleCategory.INJECTION).count()).isEqualTo(450L);
        assertThat(response.byCategory().get(RuleCategory.INJECTION).avgThreatScore()).isEqualTo(72.3);

        assertThat(response.byAction()).containsEntry(Action.DENY, 890L);

        assertThat(response.topAttackers()).hasSize(1);
        assertThat(response.topAttackers().get(0).clientIp()).isEqualTo("203.0.113.42");
        assertThat(response.topAttackers().get(0).count()).isEqualTo(87L);
        assertThat(response.topAttackers().get(0).avgThreatScore()).isEqualTo(81.2);

        assertThat(response.topTargetedPaths()).hasSize(1);
        assertThat(response.topTargetedPaths().get(0).path()).isEqualTo("/api/v1/login");
        assertThat(response.topTargetedPaths().get(0).count()).isEqualTo(234L);
    }

    @Test
    void configIdIsPassedToEveryRepositoryQueryWhenPresent() {
        when(repository.countByReceivedAtRange(14227L, FROM, TO)).thenReturn(0L);

        service().getSummary(14227L, FROM, TO);

        verify(repository).countByReceivedAtRange(14227L, FROM, TO);
        verify(repository).aggregateByCategory(14227L, FROM, TO);
        verify(repository).aggregateByAction(14227L, FROM, TO);
        verify(repository).findTopAttackers(14227L, FROM, TO, TOP_10);
        verify(repository).findTopTargetedPaths(14227L, FROM, TO, TOP_10);
    }

    @Test
    void nullConfigIdIsPassedToEveryRepositoryQueryWhenAbsent() {
        when(repository.countByReceivedAtRange(isNull(), eq(FROM), eq(TO))).thenReturn(0L);

        service().getSummary(null, FROM, TO);

        verify(repository).countByReceivedAtRange(isNull(), eq(FROM), eq(TO));
        verify(repository).aggregateByCategory(isNull(), eq(FROM), eq(TO));
        verify(repository).aggregateByAction(isNull(), eq(FROM), eq(TO));
        verify(repository).findTopAttackers(isNull(), eq(FROM), eq(TO), eq(TOP_10));
        verify(repository).findTopTargetedPaths(isNull(), eq(FROM), eq(TO), eq(TOP_10));
    }

    @Test
    void emptyProjectionResultsProduceEmptyMapsAndLists() {
        when(repository.countByReceivedAtRange(null, FROM, TO)).thenReturn(0L);
        when(repository.aggregateByCategory(null, FROM, TO)).thenReturn(List.of());
        when(repository.aggregateByAction(null, FROM, TO)).thenReturn(List.of());
        when(repository.findTopAttackers(null, FROM, TO, TOP_10)).thenReturn(List.of());
        when(repository.findTopTargetedPaths(null, FROM, TO, TOP_10)).thenReturn(List.of());

        StatsSummaryResponse response = service().getSummary(null, FROM, TO);

        assertThat(response.configId()).isNull();
        assertThat(response.totalEvents()).isZero();
        assertThat(response.byCategory()).isEmpty();
        assertThat(response.byAction()).isEmpty();
        assertThat(response.topAttackers()).isEmpty();
        assertThat(response.topTargetedPaths()).isEmpty();
    }
}
