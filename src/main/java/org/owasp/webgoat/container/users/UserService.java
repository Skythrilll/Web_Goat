package org.owasp.webgoat.container.users;

import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;
import lombok.AllArgsConstructor;
import org.flywaydb.core.Flyway;
import org.owasp.webgoat.container.lessons.Initializeable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author nbaars
 * @since 3/19/17.
 */
@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

  private static final Pattern USERNAME_PATTERN = Pattern.compile("[a-z0-9-]{6,45}");

  private final UserRepository userRepository;
  private final UserTrackerRepository userTrackerRepository;
  private final JdbcTemplate jdbcTemplate;
  private final Function<String, Flyway> flywayLessons;
  private final List<Initializeable> lessonInitializables;

  @Override
  public WebGoatUser loadUserByUsername(String username) throws UsernameNotFoundException {
    WebGoatUser webGoatUser = userRepository.findByUsername(username);
    if (webGoatUser == null) {
      throw new UsernameNotFoundException("User not found");
    } else {
      webGoatUser.createUser();
      lessonInitializables.forEach(l -> l.initialize(webGoatUser));
    }
    return webGoatUser;
  }

  public void addUser(String username, String password) {
    var validatedUsername = validateUsername(username);

    // get user if there exists one by the name
    var userAlreadyExists = userRepository.existsByUsername(validatedUsername);
    var webGoatUser = userRepository.save(new WebGoatUser(validatedUsername, password));

    if (!userAlreadyExists) {
      userTrackerRepository.save(
          new UserTracker(
              validatedUsername)); // if user previously existed it will not get another tracker
      createLessonsForUser(webGoatUser);
    }
  }

  private void createLessonsForUser(WebGoatUser webGoatUser) {
    var schemaName = validateUsername(webGoatUser.getUsername());
    jdbcTemplate.execute(
        "CREATE SCHEMA \"" + escapeSqlIdentifier(schemaName) + "\" authorization dba");
    flywayLessons.apply(schemaName).migrate();
  }

  private String validateUsername(String username) {
    if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
      throw new IllegalArgumentException("Invalid username format");
    }
    return username;
  }

  private String escapeSqlIdentifier(String identifier) {
    return identifier.replace("\"", "\"\"");
  }

  public List<WebGoatUser> getAllUsers() {
    return userRepository.findAll();
  }
}
