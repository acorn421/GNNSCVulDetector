/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a configurable burnCallback contract after the balance check but before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Setup Transaction**: Attacker deploys malicious contract and somehow gets burnCallback set to their contract address (through governance, admin function, or social engineering)
 * 
 * 2. **Initial State Accumulation**: Attacker accumulates tokens through normal operations (transfer, mint, etc.)
 * 
 * 3. **Exploitation Transaction 1**: Attacker calls burn() with a significant amount
 *    - Balance check passes (require(balanceOf[msg.sender] >= _value))
 *    - External call to malicious burnCallback contract is made
 *    - Malicious contract receives control BEFORE state updates
 * 
 * 4. **Reentrancy Exploitation**: From within the callback, malicious contract can:
 *    - Call transfer() to move tokens while balance hasn't been updated yet
 *    - Call approve() to grant allowances based on un-updated balance
 *    - Call other functions that depend on the current balance state
 * 
 * 5. **State Inconsistency**: After callback returns, original burn continues with outdated balance assumptions, completing the burn operation on already-transferred tokens
 * 
 * **Why Multi-Transaction Required:**
 * - Transaction 1: Setup burnCallback address (requires administrative access or governance)
 * - Transaction 2: Accumulate tokens for the attack
 * - Transaction 3: Execute burn() which triggers the reentrancy
 * - The vulnerability depends on persistent state (burnCallback address) set in previous transactions
 * - The exploit leverages accumulated token balance from previous transactions
 * - State changes (burnCallback setting) must persist between transactions for the attack to work
 * 
 * **State Persistence Dependency:**
 * The vulnerability is only exploitable if:
 * - burnCallback was previously set to attacker's contract (persistent state)
 * - Attacker has accumulated sufficient token balance (persistent state)
 * - The combination of these persistent state elements enables the multi-transaction exploit
 * 
 * Note: This assumes the contract has a burnCallback state variable and corresponding setter function, which would be realistic additions to token contracts for integration with DeFi protocols.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract HKTToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Burn(address indexed from, uint256 value);

    address public burnCallback; // Added missing declaration

    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burn callback contract if set
        if (burnCallback != address(0)) {
            tokenRecipient(burnCallback).receiveApproval(msg.sender, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}