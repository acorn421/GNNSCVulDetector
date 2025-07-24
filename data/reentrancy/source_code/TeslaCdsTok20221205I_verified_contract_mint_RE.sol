/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple sequential mint transactions to exploit effectively:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokensReceived` callback
 * 2. **Transaction 2 (Initial Mint)**: Owner calls mint() to attacker's contract, triggering the callback
 * 3. **Transaction 3+ (Reentrancy Chain)**: During callback, attacker's contract re-enters mint() multiple times, exploiting the fact that balances/totalSupply are updated after the external call
 * 
 * **State Persistence Requirement:**
 * - Each mint transaction accumulates tokens in balances[_to] and increases totalSupply
 * - The vulnerability leverages the persistent state changes across multiple transactions
 * - Attacker builds up token balance through successive reentrancy attacks across different mint operations
 * 
 * **Multi-Transaction Necessity:**
 * - Single transaction reentrancy would be limited by gas constraints and the onlyOwner modifier
 * - The real exploitation requires the owner to call mint() multiple times over different transactions
 * - Each transaction compounds the previous state changes, allowing the attacker to accumulate more tokens than intended
 * - The vulnerability becomes more severe with each subsequent mint transaction that triggers the callback
 * 
 * This creates a realistic scenario where a token contract with notification features becomes vulnerable to accumulated reentrancy attacks across multiple minting operations.
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract TeslaCdsTok20221205I is Ownable {
    
    string public constant name = "TeslaCdsTok20221205I";
    
    string public constant symbol = "TESLAII";
    
    uint32 public constant decimals = 8;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External call before state update (CEI violation)
        // Notify recipient contract of incoming tokens
        if(isContract(_to)) {
            // Only attempt notification if _to is a contract
            // Use low-level call to maintain the vulnerability
            bytes4 sig = bytes4(keccak256("onTokensReceived(address,uint256)"));
            bool success = _to.call(sig, msg.sender, _value);
            require(success, "Token notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        totalSupply += _value;
    }
    
    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value; 
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value; 
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
    // Helper function to check if address is a contract for Solidity ^0.4.x
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
