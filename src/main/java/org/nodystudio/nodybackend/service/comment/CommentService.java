package org.nodystudio.nodybackend.service.comment;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nodystudio.nodybackend.domain.comment.Comment;
import org.nodystudio.nodybackend.domain.thread.Thread;
import org.nodystudio.nodybackend.domain.user.User;
import org.nodystudio.nodybackend.dto.comment.CommentCreateRequest;
import org.nodystudio.nodybackend.dto.comment.CommentResponse;
import org.nodystudio.nodybackend.dto.comment.CommentUpdateRequest;
import org.nodystudio.nodybackend.event.CommentMentionEvent;
import org.nodystudio.nodybackend.exception.custom.BadRequestException;
import org.nodystudio.nodybackend.exception.custom.ResourceNotFoundException;
import org.nodystudio.nodybackend.exception.custom.UnauthorizedException;
import org.nodystudio.nodybackend.exception.custom.UserNotFoundException;
import org.nodystudio.nodybackend.repository.CommentRepository;
import org.nodystudio.nodybackend.repository.ThreadRepository;
import org.nodystudio.nodybackend.repository.UserRepository;
import org.nodystudio.nodybackend.util.HtmlSanitizerUtil;
import org.nodystudio.nodybackend.util.LoggingUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 댓글 관리 서비스
 *
 * <p>
 * 스레드에 대한 댓글 생성, 조회, 수정, 삭제 기능을 제공합니다. 사용자 멘션 기능을 지원하며, 멘션 알림은 비동기 이벤트로 처리됩니다.
 * 계층형 댓글 구조를 지원하여 대댓글
 * 작성이 가능합니다.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CommentService {

  private static final Pattern MENTION_PATTERN = Pattern.compile("@([a-zA-Z가-힣_][a-zA-Z0-9가-힣_]*)");

  private final CommentRepository commentRepository;
  private final ThreadRepository threadRepository;
  private final UserRepository userRepository;
  private final ApplicationEventPublisher eventPublisher;

  /**
   * 새로운 댓글을 생성합니다.
   *
   * @param threadId  스레드 ID
   * @param request   댓글 생성 요청 정보
   * @param userEmail 댓글 작성자의 이메일
   * @return 생성된 댓글 정보
   * @throws ResourceNotFoundException 스레드나 부모 댓글을 찾을 수 없는 경우
   * @throws UserNotFoundException     사용자를 찾을 수 없는 경우
   * @throws BadRequestException       유효하지 않은 요청인 경우
   */
  @Transactional
  public CommentResponse createComment(Long threadId, CommentCreateRequest request,
      String userEmail) {
    log.info("댓글 생성 요청 - 스레드: {}, 사용자: {}, 부모댓글: {}",
        threadId, userEmail, request.getParentId());

    User author = findUserByEmail(userEmail);
    Thread thread = findThread(threadId);

    // 부모 댓글 검증 (대댓글인 경우)
    Comment parent = null;
    if (request.getParentId() != null) {
      parent = validateAndGetParentComment(request.getParentId(), threadId);
    }

    // XSS 공격 방지를 위한 HTML sanitization
    String sanitizedContent = HtmlSanitizerUtil.sanitizeCommentContent(request.getContent());

    // 멘션된 사용자 파싱 (원본 내용 기준)
    // Sanitizer가 멘션을 포함한 HTML을 제거할 수 있으므로, 반드시 원본 내용에서 멘션을 파싱해야 합니다.
    Set<User> mentionedUsers = parseMentionedUsers(request.getContent());

    Comment comment = Comment.builder()
        .thread(thread)
        .author(author)
        .content(sanitizedContent)
        .parent(parent)
        .build();

    // 멘션된 사용자들을 추가
    for (User mentionedUser : mentionedUsers) {
      comment.addMentionedUser(mentionedUser);
    }

    Comment savedComment = commentRepository.save(comment);
    thread.addComment(savedComment);

    if (!mentionedUsers.isEmpty()) {
      publishMentionEvent(savedComment, mentionedUsers);
    }

    log.info("댓글 생성 완료 - ID: {}, HTML sanitization 적용됨", savedComment.getId());

    return CommentResponse.from(savedComment);
  }

  /**
   * 스레드의 모든 댓글을 계층 구조로 조회합니다.
   *
   * @param threadId 스레드 ID
   * @return 계층형 댓글 목록
   * @throws ResourceNotFoundException 스레드를 찾을 수 없는 경우
   */
  public List<CommentResponse> getThreadComments(Long threadId) {
    log.info("스레드 댓글 조회 요청 - 스레드: {}", threadId);

    // 스레드 존재 여부 확인
    if (!threadRepository.existsById(threadId)) {
      throw new ResourceNotFoundException("스레드를 찾을 수 없습니다: " + threadId);
    }

    // 모든 댓글을 한 번에 조회 (N+1 쿼리 방지)
    List<Comment> allComments = commentRepository.findByThreadIdWithAuthorAndMentions(threadId);

    // 계층 구조로 변환
    List<CommentResponse> hierarchicalComments = buildCommentHierarchy(allComments);

    log.info("스레드 댓글 조회 완료 - 총 댓글 수: {}", allComments.size());
    return hierarchicalComments;
  }

  /**
   * 댓글을 수정합니다.
   *
   * @param commentId 댓글 ID
   * @param request   댓글 수정 요청 정보
   * @param userEmail 수정 요청자의 이메일
   * @return 수정된 댓글 정보
   * @throws ResourceNotFoundException 댓글을 찾을 수 없는 경우
   * @throws UnauthorizedException     수정 권한이 없는 경우
   * @throws BadRequestException       삭제된 댓글을 수정하려는 경우
   */
  @Transactional
  public CommentResponse updateComment(Long commentId, CommentUpdateRequest request,
      String userEmail) {
    log.info("댓글 수정 요청 - ID: {}, 사용자: {}", commentId, userEmail);

    User user = findUserByEmail(userEmail);
    Comment comment = findUserOwnedComment(commentId, user.getId());

    if (comment.isDeleted()) {
      throw new BadRequestException("삭제된 댓글은 수정할 수 없습니다.");
    }

    // XSS 공격 방지를 위한 HTML sanitization
    String sanitizedContent = HtmlSanitizerUtil.sanitizeCommentContent(request.getContent());

    // 멘션된 사용자 파싱 (원본 내용 기준)
    // Sanitizer가 멘션을 포함한 HTML을 제거할 수 있으므로, 반드시 원본 내용에서 멘션을 파싱해야 합니다.
    Set<User> newMentionedUsers = parseMentionedUsers(request.getContent());
    List<User> previousMentions = new ArrayList<>(comment.getMentionedUsers());

    comment.updateContent(sanitizedContent);
    comment.setMentionedUsers(new ArrayList<>(newMentionedUsers));

    // 새로 추가된 멘션에 대해서만 알림 발행
    Set<User> addedMentions = newMentionedUsers.stream()
        .filter(u -> !previousMentions.contains(u))
        .collect(Collectors.toSet());

    if (!addedMentions.isEmpty()) {
      publishMentionEvent(comment, addedMentions);
      log.info("댓글 수정 시 새로운 멘션 발행 - 댓글: {}, 새 멘션: {}명",
          commentId, addedMentions.size());
    }

    log.info("댓글 수정 완료 - ID: {}, HTML sanitization 적용됨", commentId);
    return CommentResponse.from(comment);
  }

  /**
   * 댓글을 삭제합니다 (소프트 삭제).
   *
   * @param commentId 댓글 ID
   * @param userEmail 삭제 요청자의 이메일
   * @throws ResourceNotFoundException 댓글을 찾을 수 없는 경우
   * @throws UnauthorizedException     삭제 권한이 없는 경우
   * @throws BadRequestException       이미 삭제된 댓글인 경우
   */
  @Transactional
  public void deleteComment(Long commentId, String userEmail) {
    log.info("댓글 삭제 요청 - ID: {}, 사용자: {}", commentId, userEmail);

    User user = findUserByEmail(userEmail);
    Comment comment = findUserOwnedComment(commentId, user.getId());

    if (comment.isDeleted()) {
      throw new BadRequestException("이미 삭제된 댓글입니다.");
    }

    // 소프트 삭제 처리 (@SQLDelete 어노테이션에 의해 deletedAt이 설정됨)
    commentRepository.delete(comment);

    log.info("댓글 삭제 완료 - ID: {}", commentId);
  }

  /**
   * 사용자가 작성한 댓글 목록을 조회합니다.
   *
   * @param userEmail 사용자 이메일
   * @param pageable  페이징 정보
   * @return 댓글 목록
   */
  public Page<CommentResponse> getUserComments(String userEmail, Pageable pageable) {
    log.info("사용자 댓글 조회 요청 - 사용자: {}", userEmail);

    User user = findUserByEmail(userEmail);
    Page<Comment> comments = commentRepository.findByAuthorIdAndDeletedAtIsNullOrderByCreatedAtDesc(user.getId(),
        pageable);

    return comments.map(CommentResponse::from);
  }

  /**
   * 사용자가 멘션된 댓글 목록을 조회합니다.
   *
   * @param userEmail 사용자 이메일
   * @param pageable  페이징 정보
   * @return 멘션된 댓글 목록
   */
  public Page<CommentResponse> getMentionedComments(String userEmail, Pageable pageable) {
    log.info("멘션된 댓글 조회 요청 - 사용자: {}", userEmail);

    User user = findUserByEmail(userEmail);
    Page<Comment> comments = commentRepository.findByMentionedUserId(user.getId(), pageable);

    return comments.map(CommentResponse::from);
  }

  /**
   * 스레드의 댓글 개수를 조회합니다.
   *
   * @param threadId 스레드 ID
   * @return 활성 댓글 개수
   */
  public long getCommentCount(Long threadId) {
    return commentRepository.countByThreadIdAndDeletedAtIsNull(threadId);
  }

  // === Private Helper Methods ===

  private User findUserByEmail(String email) {
    return userRepository.findByEmailAndIsActiveTrue(email)
        .orElseThrow(() -> new UserNotFoundException("사용자를 찾을 수 없습니다: " + email));
  }

  private Thread findThread(Long threadId) {
    return threadRepository.findById(threadId)
        .orElseThrow(() -> new ResourceNotFoundException("스레드를 찾을 수 없습니다: " + threadId));
  }

  private Comment findUserOwnedComment(Long commentId, Long userId) {
    return commentRepository.findByIdAndAuthorIdAndDeletedAtIsNull(commentId, userId)
        .orElseThrow(() -> new ResourceNotFoundException("댓글을 찾을 수 없습니다. (ID: " + commentId + ")"));
  }

  private Comment validateAndGetParentComment(Long parentId, Long threadId) {
    Comment parent = commentRepository.findById(parentId)
        .orElseThrow(() -> new ResourceNotFoundException("부모 댓글을 찾을 수 없습니다: " + parentId));

    if (!parent.getThread().getId().equals(threadId)) {
      throw new BadRequestException("부모 댓글이 다른 스레드에 속해 있습니다.");
    }

    if (parent.isDeleted()) {
      throw new BadRequestException("삭제된 댓글에는 답글을 작성할 수 없습니다.");
    }

    return parent;
  }

  /**
   * 댓글 내용에서 멘션된 사용자들을 파싱합니다.
   *
   * @param content 댓글 내용
   * @return 멘션된 사용자들의 Set
   */
  private Set<User> parseMentionedUsers(String content) {
    Set<User> mentionedUsers = new HashSet<>();
    Matcher matcher = MENTION_PATTERN.matcher(content);

    while (matcher.find()) {
      String nickname = matcher.group(1);
      log.debug("멘션 파싱 중 - 닉네임: {}", nickname);

      userRepository.findByNicknameAndIsActiveTrue(nickname)
          .ifPresent(user -> {
            mentionedUsers.add(user);
            log.debug("멘션된 사용자 찾음 - 닉네임: {}, ID: {}", nickname, user.getId());
          });
    }

    log.info("멘션 파싱 완료 - 총 {}명의 사용자 멘션됨", mentionedUsers.size());
    return mentionedUsers;
  }

  /**
   * 댓글 목록을 계층 구조로 변환합니다.
   */
  private List<CommentResponse> buildCommentHierarchy(List<Comment> comments) {
    Map<Long, CommentResponse> commentMap = new HashMap<>();
    List<CommentResponse> rootComments = new ArrayList<>();

    // 모든 댓글을 CommentResponse로 변환하고 맵에 저장
    for (Comment comment : comments) {
      CommentResponse response = CommentResponse.from(comment);
      commentMap.put(comment.getId(), response);
    }

    // 계층 구조 구성
    for (Comment comment : comments) {
      CommentResponse response = commentMap.get(comment.getId());

      if (comment.isRootComment()) {
        rootComments.add(response);
      } else if (comment.getParent() != null) {
        CommentResponse parentResponse = commentMap.get(comment.getParent().getId());
        if (parentResponse != null) {
          parentResponse.addChild(response);
        }
      }
    }

    return rootComments;
  }

  /**
   * 멘션 알림 이벤트를 발행합니다.
   *
   * @param comment        댓글 정보
   * @param mentionedUsers 멘션된 사용자들
   */
  private void publishMentionEvent(Comment comment, Set<User> mentionedUsers) {
    CommentMentionEvent event = new CommentMentionEvent(
        comment.getId(),
        comment.getAuthor().getId(),
        comment.getThread().getId(),
        mentionedUsers.stream()
            .map(User::getId)
            .collect(Collectors.toSet()));

    eventPublisher.publishEvent(event);
    log.info("멘션 알림 이벤트 발행 - 댓글: {}, 멘션된 사용자: {}명",
        comment.getId(), mentionedUsers.size());
  }

  /**
   * 특정 사용자의 모든 활성 댓글을 비활성화합니다.
   * 계정 탈퇴 시 사용자 생성 데이터를 안전하게 보존하면서 조회에서 제외시킵니다.
   *
   * @param userId 비활성화할 사용자 ID
   * @return 비활성화된 댓글의 개수
   */
  @Transactional
  public int deactivateCommentsByUserId(Long userId) {
    log.debug("사용자 댓글 비활성화 시작: userId={}", LoggingUtils.maskUserId(userId));

    int deactivatedCount = commentRepository.deactivateByUserId(userId);

    log.debug("사용자 댓글 비활성화 완료: userId={}, count={}",
        LoggingUtils.maskUserId(userId), deactivatedCount);

    return deactivatedCount;
  }

  /**
   * 특정 사용자의 모든 비활성화된 댓글을 재활성화합니다.
   * 계정 복구 시 다시 조회 가능하도록 복원합니다.
   *
   * @param userId 재활성화할 사용자 ID
   * @return 재활성화된 댓글의 개수
   */
  @Transactional
  public int reactivateCommentsByUserId(Long userId) {
    log.debug("사용자 댓글 재활성화 시작: userId={}", LoggingUtils.maskUserId(userId));

    int reactivatedCount = commentRepository.reactivateByUserId(userId);

    log.debug("사용자 댓글 재활성화 완료: userId={}, count={}",
        LoggingUtils.maskUserId(userId), reactivatedCount);

    return reactivatedCount;
  }
}