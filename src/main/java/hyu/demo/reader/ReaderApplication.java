package hyu.demo.reader;

import hyu.demo.reader.config.EnvConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ReaderApplication {

    public static void main(String[] args) {
        EnvConfig.loadEnvironmentVariables();
        
        SpringApplication.run(ReaderApplication.class, args);
    }
}