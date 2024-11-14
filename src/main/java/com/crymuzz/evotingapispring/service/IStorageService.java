package com.crymuzz.evotingapispring.service;

import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface IStorageService {

    void init() throws IOException;
    String store(MultipartFile file);
    Resource loadSource(String filename);

}
