/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Details:**
 * 
 * **1. Specific Code Changes Made:**
 * - Added an external call to `tokenRecipient(msg.sender).receiveApproval()` after state updates
 * - The external call is triggered only when `msg.sender` is a contract (has code)
 * - Used try-catch to handle potential failures while maintaining the reentrancy window
 * - The external call occurs after critical state changes (balanceOf and totalSupply updates)
 * 
 * **2. Multi-Transaction Exploitation Pattern:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract calls `burn()` with legitimate amount
 * - State is updated (balanceOf decreased, totalSupply decreased)
 * - External call triggers attacker's `receiveApproval()` function
 * - During callback, attacker can call other functions or set up state for future exploitation
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker can now exploit the persistent state changes from Transaction 1
 * - The attacker's contract can call `burn()` again, potentially with manipulated state
 * - Since state persists between transactions, the attacker can accumulate advantages
 * 
 * **3. Why Multi-Transaction Dependency is Critical:**
 * - **State Persistence**: The `balanceOf` and `totalSupply` changes persist between transactions
 * - **Accumulated Effects**: Each burn operation creates persistent state changes that can be leveraged in subsequent transactions
 * - **Cross-Transaction State Manipulation**: The external call allows attackers to set up state in one transaction that affects vulnerability in future transactions
 * - **Timing Dependencies**: The vulnerability depends on the sequence of state changes across multiple burn operations
 * 
 * **4. Realistic Attack Scenario:**
 * 1. Attacker deploys a malicious contract that implements `receiveApproval`
 * 2. In Transaction 1: Attacker calls `burn()`, state is updated, external call triggers
 * 3. During external call, attacker can interact with other contracts or prepare for future exploitation
 * 4. In Transaction 2: Attacker can leverage the accumulated state changes from previous burns
 * 5. The vulnerability compounds across multiple burn operations, creating exploitable conditions
 * 
 * **5. Stateful Nature:**
 * - Each burn operation leaves persistent state changes in `balanceOf` and `totalSupply`
 * - The external call window allows attackers to prepare for future transactions
 * - The vulnerability requires building up exploitable state across multiple function calls
 * - Single-transaction exploitation is prevented by the require check, but multi-transaction exploitation is possible through accumulated state manipulation
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract YoungToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);

    function YoungToken(
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
        balanceOf[msg.sender] -= _value;          
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        totalSupply -= _value;

        // Notify burning contract about the burn operation
        if (isContract(msg.sender)) {
            tokenRecipient(msg.sender).receiveApproval(msg.sender, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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