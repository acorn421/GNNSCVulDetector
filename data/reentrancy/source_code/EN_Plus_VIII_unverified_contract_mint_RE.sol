/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * 1. **Transaction 1 - Setup**: Attacker deploys a malicious contract with `onTokensMinted()` function that re-enters the `mint()` function
 * 2. **Transaction 2 - Initial Mint**: Owner calls `mint()` with the malicious contract as `_to`
 *    - State is updated first (balances and totalSupply increased)
 *    - External call triggers malicious contract's `onTokensMinted()`
 *    - Malicious contract can re-enter `mint()` multiple times since state was already updated
 *    - Each re-entry bypasses the overflow checks as balances were already increased
 * 3. **Transaction 3+ - Exploitation**: Attacker uses over-minted tokens in subsequent transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy a malicious contract (separate transaction)
 * - The reentrancy occurs during the owner's mint call, but the malicious contract must be pre-deployed
 * - The over-minted tokens persist in state and can only be exploited in subsequent transactions
 * - The vulnerability creates a stateful condition where the contract holds more tokens than intended
 * 
 * **State Persistence Aspect:**
 * - The vulnerability results in permanently increased balances and totalSupply
 * - These state changes persist across transactions
 * - The exploit requires the accumulated state from multiple re-entrant calls within a single transaction, but the setup and exploitation span multiple transactions
 * 
 * The external call appears legitimate (notifying recipients of minted tokens) but violates the Checks-Effects-Interactions pattern by occurring after state changes.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract EN_Plus_VIII is Ownable {

    string public constant name = "\tEN_Plus_VIII\t\t";
    string public constant symbol = "\tENPVIII\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient of minted tokens - vulnerable to reentrancy
        if (isContract(_to)) {
            // Use low-level call for reentrancy, as in original
            (bool success,) = _to.call(abi.encodeWithSignature("onTokensMinted(uint256)", _value));
            require(success, "Callback failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function isContract(address _addr) private view returns (bool is_contract) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
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
