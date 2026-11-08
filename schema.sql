-- Peer Evaluation System Database Schema
CREATE DATABASE IF NOT EXISTS peer_eval_db;
USE peer_eval_db;

-- 1. Groups Table
CREATE TABLE IF NOT EXISTS groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Users Table (Admin & Students)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'student') DEFAULT 'student',
    group_id INT NULL,
    is_leader TINYINT(1) DEFAULT 0,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL
);

-- 3. Peer Evaluation Submissions
CREATE TABLE IF NOT EXISTS peer_evaluations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_id INT NOT NULL,
    evaluator_id INT NOT NULL,
    evaluatee_id INT NOT NULL,
    course_subject VARCHAR(100),
    project_title VARCHAR(200),
    perf_avg DECIMAL(3,2) NOT NULL,
    fin_avg DECIMAL(3,2) NOT NULL,
    overall_weighted_score DECIMAL(5,2) NOT NULL,
    score_interpretation VARCHAR(50) NOT NULL,
    fin_agreed_responsibility TEXT,
    fin_agreed_amount DECIMAL(10,2) DEFAULT 0.00,
    fin_actual_contributed DECIMAL(10,2) DEFAULT 0.00,
    fin_unpaid_balance DECIMAL(10,2) DEFAULT 0.00,
    fin_was_agreed ENUM('Yes', 'No', 'N/A') DEFAULT 'N/A',
    fin_limitations_communicated ENUM('Yes', 'No', 'N/A') DEFAULT 'N/A',
    comments_contributions TEXT,
    comments_failures TEXT,
    comments_additional TEXT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id),
    FOREIGN KEY (evaluator_id) REFERENCES users(id),
    FOREIGN KEY (evaluatee_id) REFERENCES users(id),
    UNIQUE KEY unique_peer_eval (group_id, evaluator_id, evaluatee_id)
);

-- 4. Criteria Breakdown (12 Criteria per evaluation)
CREATE TABLE IF NOT EXISTS evaluation_criteria_ratings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evaluation_id INT NOT NULL,
    criterion_number INT NOT NULL,
    rating_value VARCHAR(5) NOT NULL,
    FOREIGN KEY (evaluation_id) REFERENCES peer_evaluations(id) ON DELETE CASCADE
);

-- Seed Default Admin User (Password: admin123)
INSERT INTO users (full_name, email, password_hash, role) 
VALUES ('System Administrator', 'admin@school.edu', '$2b$10$wT5Wp5o/JzUqHh6G.e5/quh44R5K9b/2wFv1z/7zNn7k7q0gZ3W.O', 'admin')
ON DUPLICATE KEY UPDATE id=id;
