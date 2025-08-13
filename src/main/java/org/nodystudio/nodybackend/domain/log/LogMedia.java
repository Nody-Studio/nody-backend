package org.nodystudio.nodybackend.domain.log;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Index;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.nodystudio.nodybackend.domain.BaseTimeEntity;

/**
 * Represents a media item associated with a Log.
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = "log_media", indexes = {
    @Index(name = "idx_log_media_log_id", columnList = "log_id"),
    @Index(name = "idx_log_media_sort_index", columnList = "sort_index")
})
public class LogMedia extends BaseTimeEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "log_media_id")
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "log_id", nullable = false)
  private Log log;

  @Column(name = "url", length = 500, nullable = false)
  private String url;

  @Column(name = "sort_index", nullable = false)
  @Builder.Default
  private Integer sortIndex = 0;

  /**
   * Sets parent log and maintains bidirectional relationship consistency.
   */
  public LogMedia assignTo(Log log) {
    // Remove from current log's collection if exists
    if (this.log != null) {
      this.log.getMediaList().remove(this);
    }
    
    // Set new log reference
    this.log = log;
    
    // Add to new log's collection if not already present
    if (log != null && !log.getMediaList().contains(this)) {
      log.getMediaList().add(this);
    }
    
    return this;
  }

  /**
   * Updates the sort index.
   */
  public void updateSortIndex(int sortIndex) {
    this.sortIndex = sortIndex;
  }
}
