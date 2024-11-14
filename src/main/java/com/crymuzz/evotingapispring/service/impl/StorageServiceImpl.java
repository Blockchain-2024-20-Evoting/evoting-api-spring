package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.service.IStorageService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

@Service
public class StorageServiceImpl implements IStorageService {

    @Value("${media.location}")
    private String location;

    private Path rootLocation;

    @Override
    @PostConstruct
    public void init() throws IOException {
        rootLocation = Paths.get(location);
        Files.createDirectories(rootLocation);
    }

    @Override
    public String store(MultipartFile file) {
        try {
            if (file.isEmpty())
                throw new IllegalArgumentException("File is empty");
            String fileName = file.getOriginalFilename();
            Path destinationFile = rootLocation.resolve(Objects.requireNonNull(fileName)).normalize().toAbsolutePath();
            try (InputStream inputStream = file.getInputStream()) {
                Files.copy(inputStream, destinationFile, StandardCopyOption.REPLACE_EXISTING);
            }
            return fileName;
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to store file", e);
        }
    }

    @Override
    public Resource loadSource(String filename) {
        try {
            Path file = rootLocation.resolve(filename);
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable())
                return resource;
            else
                throw new IllegalArgumentException("File not found");
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Failed to load file", e);
        }

    }
}
