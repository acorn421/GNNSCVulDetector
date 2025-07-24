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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. This creates a classic violation of the Checks-Effects-Interactions pattern where:
 * 
 * 1. **State Persistence**: The vulnerability leverages the fact that balances and totalSupply are persistent state variables that maintain their values across transactions.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Owner calls mint() for a malicious contract address
 *    - During the external call in Transaction 1, the malicious contract can re-enter mint() in a nested call
 *    - The nested call sees the original state (before the first mint's state updates)
 *    - Both calls will execute their state updates, leading to double minting
 *    - The vulnerability requires the owner to interact with a malicious contract across multiple call frames
 * 
 * 3. **Why Multi-Transaction**: The vulnerability cannot be exploited in a single atomic transaction because:
 *    - It requires the owner to deliberately mint tokens to a malicious contract
 *    - The malicious contract must then re-enter during the callback
 *    - The exploit depends on the state inconsistency between the initial call and the reentrant call
 *    - Each call frame represents a separate logical transaction in the call stack
 * 
 * 4. **Realistic Context**: The callback mechanism (`onTokensMinted`) is a common pattern in token contracts for notifying recipients, making this vulnerability realistic and subtle.
 * 
 * The vulnerability is stateful because it depends on the persistent state variables (balances, totalSupply) and requires multiple function calls in sequence to exploit effectively.
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

contract ValeaCdsTok20220305I is Ownable {
    
    string public constant name = "ValeaCdsTok20220305I";
    
    string public constant symbol = "VALEAI";
    
    uint32 public constant decimals = 8;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Added: External call to recipient before state updates - creates reentrancy vulnerability
        if (isContract(_to)) {
            // Callback to notify the recipient about minting
            _to.call(abi.encodeWithSignature("onTokensMinted(uint256)", _value));
            // Continue even if callback fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        totalSupply += _value;
    }
    
    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
    
}
