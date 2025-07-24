/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` with `onTokenReceived` callback before the allowance update
 * 2. Used low-level call to avoid compilation errors if recipient doesn't implement the interface
 * 3. Positioned the external call after the allowance check but before the allowance state update
 * 4. Maintained original function signature and core functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase (Transaction 1)**: Victim approves attacker contract for a certain allowance amount
 * 2. **Exploitation Phase (Transaction 2)**: Attacker calls transferFrom with malicious contract as `_to`
 * 3. **Reentrancy Window**: The malicious contract's `onTokenReceived` function re-enters transferFrom before allowance is decremented
 * 4. **State Persistence**: The allowance state remains unchanged between the initial check and the delayed update, enabling multiple uses of the same allowance across transactions
 * 5. **Repeated Exploitation**: Attacker can drain more tokens than originally approved by exploiting the timing window
 * 
 * **Why Multiple Transactions Are Required:**
 * - The allowance must be set up in a prior transaction (via approve() call)
 * - The vulnerability exploits the persistent state of the allowance mapping between transactions
 * - The reentrancy attack requires the external call to trigger additional transferFrom calls before the current one completes its state update
 * - Each reentrant call checks against the same unchanged allowance value, allowing multiple withdrawals
 * - The attack accumulates effects across multiple function calls, making it stateful and multi-transaction dependent
 * 
 * This creates a realistic Checks-Effects-Interactions pattern violation where the external interaction occurs before the critical state update, enabling classic reentrancy exploitation that spans multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract AZEEMCOIN {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    uint256 public sellPrice = 1;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function AZEEMCOIN(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals); 
        balanceOf[msg.sender] = totalSupply;         
        name = tokenName;                             
        symbol = tokenSymbol;                               
    }

    function _isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Use _isContract utility for contract detection, preserve injected call and naming
        if (_isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
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
