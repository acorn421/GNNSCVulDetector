/*
 * ===== SmartInject Injection Details =====
 * Function      : payForStore
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables**: 
 *    - `pendingPayments` mapping to track accumulated pending payments across transactions
 *    - `paymentProcessing` boolean mapping to manage payment processing state
 * 
 * 2. **External Call Integration**: Added a realistic external call to `storeAccountAddress` for payment notifications, which is common in e-commerce systems
 * 
 * 3. **Violated Checks-Effects-Interactions**: The external call now occurs BEFORE the critical state updates (balance transfers), creating a reentrancy window
 * 
 * 4. **Multi-Transaction State Management**: The `pendingPayments` and `paymentProcessing` mappings persist between transactions, enabling complex attack scenarios
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `payForStore(100)` 
 * - `paymentProcessing[attacker] = true`
 * - `pendingPayments[attacker] = 100`
 * - External call to malicious store contract triggers
 * - Malicious contract notes the pending payment but doesn't immediately attack
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker's malicious contract calls `payForStore(50)` from a different context
 * - Since `paymentProcessing` was reset to false in Transaction 1, the call proceeds
 * - The malicious contract can now manipulate the accumulated `pendingPayments` state
 * - During the external call, the malicious contract can call back into other functions or manipulate state based on the accumulated pending payments
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Accumulation**: The `pendingPayments` mapping accumulates values across multiple calls, creating exploitable state that builds up over time
 * 
 * 2. **Processing Flag Reset**: The `paymentProcessing` flag is reset at the end of each transaction, allowing subsequent transactions to bypass the direct reentrancy protection
 * 
 * 3. **External Contract State**: The malicious store contract can maintain its own state between transactions, planning complex attacks based on accumulated pending payments
 * 
 * 4. **Cross-Transaction Timing**: The vulnerability exploits the window between when `pendingPayments` is updated and when balances are actually transferred, but this window spans multiple transactions due to the external call pattern
 * 
 * The vulnerability is realistic because it mimics real-world payment processing systems that notify external contracts and maintain pending payment states, while the multi-transaction nature reflects how sophisticated attacks can build up state over time rather than exploiting single atomic transactions.
 */
pragma solidity >=0.4.0 <0.7.0;

contract SpaciumToken {
    
    string public constant name = "Spacium Token";
    string public constant symbol = "SPC";
    uint8 public constant decimals = 18;
    
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event HostingPayment(address indexed from, uint tokens);
    event StorePayment(address indexed from, uint tokens);
    event CloudPayment(address indexed from, uint tokens);
    
    mapping(address => uint256) balances;

    mapping(address => mapping (address => uint256)) allowed;
    
    uint256 totalSupply_;
    address public constant hostingAccountAddress = 0xdc1787eF8536235198fE5aEd66Fc3A73DEd31280;
    address public constant storeAccountAddress = 0x017A759A2095841122b4b4e90e40AE579a4361f1;
    address public constant cloudAccountAddress = 0x38C6Ec7331ce04891154b953a79B157703CaE38a;
    

    using SafeMath for uint256;

    
    constructor() public{
        totalSupply_ = 21000000000000000000000000;
	    balances[msg.sender] = 21000000000000000000000000;
    }
    
    function totalSupply() public view returns (uint256) {
	    return totalSupply_;
    }
    
    function balanceOf(address tokenOwner) public view returns (uint) {
        return balances[tokenOwner];
    }
    
    function transfer(address receiver, uint numTokens) public returns (bool) {
        require(numTokens <= balances[msg.sender]);
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[receiver] = balances[receiver].add(numTokens);
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }
    
    function approve(address delegate, uint numTokens) public returns (bool) {
        allowed[msg.sender][delegate] = numTokens;
        emit Approval(msg.sender, delegate, numTokens);
        return true;
    }
    
    function allowance(address owner, address delegate) public view returns (uint) {
        return allowed[owner][delegate];
    }
    
    function transferFrom(address owner, address buyer, uint numTokens) public returns (bool) {
        require(numTokens <= balances[owner]);    
        require(numTokens <= allowed[owner][msg.sender]);
    
        balances[owner] = balances[owner].sub(numTokens);
        allowed[owner][msg.sender] = allowed[owner][msg.sender].sub(numTokens);
        balances[buyer] = balances[buyer].add(numTokens);
        emit Transfer(owner, buyer, numTokens);
        return true;
    }
    
    function payForHosting(uint numTokens) public returns (bool){
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[hostingAccountAddress] = balances[hostingAccountAddress].add(numTokens);
        emit HostingPayment(msg.sender, numTokens);
        return true;

    }
    
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public pendingPayments;
    mapping(address => bool) public paymentProcessing;
    
    function payForStore(uint numTokens) public returns (bool){
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(!paymentProcessing[msg.sender], "Payment already processing");
        
        // Mark payment as processing to prevent direct reentrancy
        paymentProcessing[msg.sender] = true;
        
        // Add to pending payments for multi-transaction vulnerability
        pendingPayments[msg.sender] = pendingPayments[msg.sender].add(numTokens);
        
        // External call to store account (if it's a contract) for payment notification
        // This creates the reentrancy opportunity across multiple transactions
        uint codeLength;
        address addr = storeAccountAddress;
        assembly { codeLength := extcodesize(addr) }
        if (codeLength > 0) {
            // Call external contract before final state updates
            (bool success, ) = storeAccountAddress.call(
                abi.encodeWithSignature("onPaymentReceived(address,uint256)", msg.sender, numTokens)
            );
            // Continue even if call fails to maintain functionality
        }
        
        // State updates occur after external call - vulnerability window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[storeAccountAddress] = balances[storeAccountAddress].add(numTokens);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Reset processing flag and pending payment
        paymentProcessing[msg.sender] = false;
        pendingPayments[msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit StorePayment(msg.sender, numTokens);
        return true;
    }
    
     function payForCloud(uint numTokens) public returns (bool){
        
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[cloudAccountAddress] = balances[cloudAccountAddress].add(numTokens);
        emit CloudPayment(msg.sender, numTokens);
        return true;
    }
}

library SafeMath { 
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
      assert(b <= a);
      return a - b;
    }
    
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
      uint256 c = a + b;
      assert(c >= a);
      return c;
    }
}