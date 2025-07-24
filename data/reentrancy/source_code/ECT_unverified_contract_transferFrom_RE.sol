/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance. The vulnerability is exploitable through the following multi-transaction sequence:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious contract and gets approved allowance from victim
 * - Calls transferFrom normally to establish trust/usage pattern
 * 
 * **Transaction 2 (Initial Exploit):**
 * - Calls transferFrom with malicious contract as _to address
 * - The external call to onTokenReceived triggers before allowance is decremented
 * - Malicious contract's onTokenReceived function can call transferFrom again
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Each reentrant call exploits the fact that allowance hasn't been updated yet
 * - Attacker can drain more tokens than originally allowed
 * - The vulnerability persists across multiple transactions due to state inconsistency
 * 
 * **Key Multi-Transaction Elements:**
 * 1. **State Accumulation**: Each transaction builds on previous state changes
 * 2. **Allowance Window**: The gap between balance updates and allowance updates creates exploitation window
 * 3. **Cross-Transaction Persistence**: The vulnerability effect accumulates across multiple calls
 * 4. **Realistic Pattern**: Token notification is a common real-world pattern that makes this vulnerability subtle
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the persistent state changes from multiple transferFrom calls to accumulate the effect and bypass the original allowance limits.
 */
pragma solidity ^0.4.24;
contract EIP20Interface {
    uint256 public totalSupply;
    // These are only function declarations in the interface, no implementation
    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract ECT is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

    constructor (
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        totalSupply = _initialAmount*10**uint256(_decimalUnits);     // Update total supply
        balances[msg.sender] = totalSupply;                          // Update total supply
        name = _tokenName;                                           // Set the name for display purposes
        decimals = _decimalUnits;                                    // Amount of decimals for display purposes
        symbol = _tokenSymbol;                                       // Set the symbol for display purposes
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    // Vulnerable transferFrom as required
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (isContract(_to)) {
            // VULNERABILITY: External call before allowance update
            (bool callSuccess, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            require(callSuccess, "Token notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    // Helper to check contract code existence (since .code not in 0.4.x)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
