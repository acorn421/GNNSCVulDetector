/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (buyer) before updating the buyer's balance. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and obtains allowance from a victim
 * 2. **Initial Call (Transaction 2)**: Attacker calls transferFrom with their malicious contract as the buyer
 * 3. **Reentrancy Exploitation**: During the external call to onTokenReceived, the malicious contract calls transferFrom again while the first call is still executing
 * 
 * The vulnerability is stateful and multi-transaction because:
 * - It requires the attacker to first set up allowances and deploy malicious contracts (separate transactions)
 * - The exploit depends on the intermediate state where allowances are already decremented but buyer balance is not yet updated
 * - The attacker can drain tokens by repeatedly calling transferFrom during the reentrancy window
 * - Each reentrant call can transfer tokens before the buyer's balance is properly updated
 * 
 * This creates a classic reentrancy vulnerability where the external call happens after allowance/owner balance updates but before buyer balance update, allowing multiple transfers with the same allowance.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify buyer contract of incoming transfer (potential reentrancy point)
        if (isContract(buyer)) {
            ITokenReceiver(buyer).onTokenReceived(owner, numTokens, msg.sender);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[buyer] = balances[buyer].add(numTokens);
        emit Transfer(owner, buyer, numTokens);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    function payForHosting(uint numTokens) public returns (bool){
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
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

interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value, address sender) external;
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
