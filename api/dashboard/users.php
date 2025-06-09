<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../../config/db.php';  // Make sure this path is correct

// Verify admin access (uncomment when ready)
// if (!isLoggedIn() || $_SESSION['user_role'] !== 'admin') {
//     http_response_code(403);
//     echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
//     exit;
// }

// Get all users with pagination
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['search'])) {
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = ($page - 1) * $limit;
    
    try {
        // Get users
        $stmt = $dbConnection->prepare("
            SELECT 
                user_id, 
                username,
                status, 
                email, 
                department,  
                created_at
            FROM users
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ");
        $stmt->bind_param("ii", $limit, $offset);
        $stmt->execute();
        $result = $stmt->get_result();
        $users = $result->fetch_all(MYSQLI_ASSOC);
        
        // Get total count for pagination
        $totalResult = $dbConnection->query("SELECT COUNT(*) FROM users");
        $total = $totalResult->fetch_row()[0];
        
        echo json_encode([
            'success' => true,
            'data' => $users,
            'pagination' => [
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'total_pages' => ceil($total / $limit)
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

// Update user status
elseif ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (empty($data['user_id']) || !isset($data['status'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        exit;
    }
    
    try {
        $stmt = $dbConnection->prepare("UPDATE users SET status = ? WHERE user_id = ?");
        $stmt->bind_param("si", $data['status'], $data['user_id']);
        $stmt->execute();
        
        if ($stmt->affected_rows > 0) {
            echo json_encode(['success' => true, 'message' => 'User status updated']);
        } else {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

// Search users
elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['search'])) {
    $search = '%' . $_GET['search'] . '%';
    
    try {
        $stmt = $dbConnection->prepare("
            SELECT 
                user_id, 
                username,
                status,  
                department,
                email
            FROM users
            WHERE 
                username LIKE ? OR
                email LIKE ? OR
                department LIKE ?
            ORDER BY created_at DESC
            LIMIT 20
        ");
        $stmt->bind_param("sss", $search, $search, $search);
        $stmt->execute();
        $result = $stmt->get_result();
        $users = $result->fetch_all(MYSQLI_ASSOC);
        
        echo json_encode(['success' => true, 'data' => $users]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}


// Create new user
elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate required fields (without password)
    $requiredFields = ['username', 'email', 'department'];
    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => "Missing required field: $field"]);
            exit;
        }
    }
    
    try {
        $stmt = $dbConnection->prepare("
            INSERT INTO users 
                (username, email, department, status, created_at)
            VALUES 
                (?, ?, ?, 'active', NOW())
        ");
        $stmt->bind_param("sss", 
            $data['username'], 
            $data['email'], 
            $data['department']
        );
        $stmt->execute();
        
        if ($stmt->affected_rows > 0) {
            $newUserId = $stmt->insert_id;
            echo json_encode([
                'success' => true,
                'message' => 'User created successfully',
                'user_id' => $newUserId
            ]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to create user']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}
?>