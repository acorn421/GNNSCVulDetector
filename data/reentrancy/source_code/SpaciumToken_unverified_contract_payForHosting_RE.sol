/*
 * ===== SmartInject Injection Details =====
 * Function      : payForHosting
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the hostingAccountAddress before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `hostingAccountAddress.call(abi.encodeWithSignature("onPaymentReceived(address,uint256)", msg.sender, numTokens))` after the initial checks but before balance updates
 * 2. This violates the Checks-Effects-Interactions pattern by placing the external call before state modifications
 * 3. The call appears realistic as payment notification systems commonly notify recipients
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract at the hostingAccountAddress (or compromises it)
 * 2. **Initial Transaction**: Attacker calls payForHosting with some tokens
 * 3. **Reentrancy Trigger**: The external call allows the malicious hostingAccountAddress to re-enter payForHosting
 * 4. **State Exploitation**: Since balance updates haven't occurred yet, the attacker can call payForHosting again with the same tokens
 * 5. **State Persistence**: The vulnerability relies on the persistent balance state across multiple calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs to first set up the malicious contract at hostingAccountAddress
 * - The initial call establishes the attack vector through the external call
 * - The reentrancy exploit depends on the state being inconsistent across multiple function calls
 * - Each reentrant call can drain additional tokens while the original balance check remains valid
 * - The accumulated effect of multiple calls (facilitated by the external call) enables the complete exploit
 * 
 * This creates a realistic vulnerability where the external call for payment notification enables reentrancy attacks that can drain user funds through multiple accumulated calls.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify hosting account about payment - external call before state updates
        (bool success, ) = hostingAccountAddress.call(abi.encodeWithSignature("onPaymentReceived(address,uint256)", msg.sender, numTokens));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[hostingAccountAddress] = balances[hostingAccountAddress].add(numTokens);
        emit HostingPayment(msg.sender, numTokens);
        return true;

    }
    
    
    function payForStore(uint numTokens) public returns (bool){
        
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[storeAccountAddress] = balances[storeAccountAddress].add(numTokens);
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