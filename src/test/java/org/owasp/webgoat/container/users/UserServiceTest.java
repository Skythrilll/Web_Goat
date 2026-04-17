package org.owasp.webgoat.container.users;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.function.Function;
import org.assertj.core.api.Assertions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

  @Mock
  private UserRepository userRepository;
  @Mock
  private UserTrackerRepository userTrackerRepository;
  @Mock
  private JdbcTemplate jdbcTemplate;
  @Mock
  private Function<String, Flyway> flywayLessons;
  @Mock
  private Flyway flyway;

  @Test
  void shouldThrowExceptionWhenUserIsNotFound() {
    when(userRepository.findByUsername(any())).thenReturn(null);
    UserService userService = new UserService(
        userRepository, userTrackerRepository, jdbcTemplate, flywayLessons, List.of());
    Assertions.assertThatThrownBy(() -> userService.loadUserByUsername("unknown"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  @Test
  void shouldRejectInvalidUsernameWhenAddingUser() {
    UserService userService = new UserService(
        userRepository, userTrackerRepository, jdbcTemplate, flywayLessons, List.of());

    Assertions.assertThatThrownBy(() -> userService.addUser("bad\"user", "secret1"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid username format");
  }

  @Test
  void shouldCreateSchemaAndRunMigrationsForValidNewUser() {
    when(userRepository.existsByUsername("test-user")).thenReturn(false);
    when(userRepository.save(any())).thenReturn(new WebGoatUser("test-user", "secret1"));
    when(flywayLessons.apply("test-user")).thenReturn(flyway);

    UserService userService = new UserService(
        userRepository, userTrackerRepository, jdbcTemplate, flywayLessons, List.of());

    userService.addUser("test-user", "secret1");

    verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"test-user\" authorization dba"));
    verify(flyway).migrate();
  }
}
