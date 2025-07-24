/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the `_from` address before state updates. This creates a callback mechanism that enables accumulated reentrancy attacks requiring multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at `_from` address using `_from.code.length > 0`
 * 2. Introduced an external call `_from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value))` 
 * 3. Positioned the external call BEFORE all state updates (balanceOf, allowance, totalSupply)
 * 4. Made the call non-reverting by ignoring the return value
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and obtains token approval
 * 2. **Accumulation Phase (Transactions 2-N)**: Attacker calls burnFrom repeatedly, each time the malicious contract's onTokenBurn callback is triggered before state updates
 * 3. **Exploitation Phase**: During each callback, the malicious contract can:
 *    - Call burnFrom again while state is inconsistent
 *    - Transfer tokens using the outdated balance/allowance state
 *    - Accumulate multiple burns using the same allowance
 *    - Drain tokens by exploiting the state inconsistency across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to set up a malicious contract first (Transaction 1)
 * - Multiple burnFrom calls are needed to accumulate sufficient state inconsistency
 * - Each callback creates a window for additional transactions that exploit the intermediate state
 * - The attacker must build up allowances and balances over multiple transactions to maximize the exploit
 * - State persistence between transactions is what makes this vulnerability devastating - single transaction reentrancy would be limited by gas and initial state
 * 
 * This creates a realistic token burning notification system that could appear in production code but introduces a severe multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.25;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract BitCredit {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Burn(address indexed from, uint256 value);
     
    constructor() public {
        totalSupply = 500000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "BitCredit";
        symbol = "BCT";
    }
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
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
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Multi-transaction vulnerability: External call before state updates
        // This creates a callback opportunity for accumulated reentrancy attacks
        if (isContract(_from)) {
            // Call external contract to notify about burn operation
            _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
