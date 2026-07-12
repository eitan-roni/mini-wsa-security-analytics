package com.eitanroni.miniwsa.persistence.repository.support;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.lang.NonNull;

/**
 * A {@link Pageable} keyed on an arbitrary absolute row offset rather than a
 * page number. {@code PageRequest.of(offset / limit, limit)} only produces
 * the intended offset when {@code offset} is a multiple of {@code limit};
 * this class reports {@link #getOffset()} directly, which Spring Data JPA
 * passes straight through to {@code Query.setFirstResult}/{@code setMaxResults}.
 */
public final class OffsetBasedPageable implements Pageable {

    private final long offset;
    private final int limit;
    private final Sort sort;

    public OffsetBasedPageable(long offset, int limit) {
        this(offset, limit, Sort.unsorted());
    }

    public OffsetBasedPageable(long offset, int limit, Sort sort) {
        if (offset < 0) {
            throw new IllegalArgumentException("Offset must not be negative");
        }
        if (limit < 1) {
            throw new IllegalArgumentException("Limit must be at least 1");
        }
        this.offset = offset;
        this.limit = limit;
        this.sort = sort;
    }

    @Override
    public int getPageNumber() {
        return (int) (offset / limit);
    }

    @Override
    public int getPageSize() {
        return limit;
    }

    @Override
    public long getOffset() {
        return offset;
    }

    @Override
    @NonNull
    public Sort getSort() {
        return sort;
    }

    @Override
    @NonNull
    public Pageable next() {
        return new OffsetBasedPageable(offset + limit, limit, sort);
    }

    @Override
    @NonNull
    public Pageable previousOrFirst() {
        return hasPrevious() ? new OffsetBasedPageable(offset - limit, limit, sort) : first();
    }

    @Override
    @NonNull
    public Pageable first() {
        return new OffsetBasedPageable(0, limit, sort);
    }

    @Override
    @NonNull
    public Pageable withPage(int pageNumber) {
        return new OffsetBasedPageable((long) pageNumber * limit, limit, sort);
    }

    @Override
    public boolean hasPrevious() {
        return offset > 0;
    }
}
