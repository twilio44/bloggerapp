package com.blog.service;

import com.blog.payload.CommentDto;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface CommentService {
    public CommentDto createComment(long postId, CommentDto commentDto);

    void deleteComment(long commentId);

    List<CommentDto> getCommentsByPostId(long postid);

    List<CommentDto> getAllComments();
}