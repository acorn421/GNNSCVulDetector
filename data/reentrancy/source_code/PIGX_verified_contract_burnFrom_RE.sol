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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the _from address before state updates. This creates a reentrancy window where the callback can manipulate allowances or trigger other functions while the original state is still unchanged.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnCallback(_from).onBurnFrom(msg.sender, _value)` before state updates
 * 2. Used try-catch to handle callback failures gracefully
 * 3. Placed the callback after validation but before balance/allowance modifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls burnFrom() on their contract, which implements IBurnCallback
 * - **Callback Phase**: The onBurnFrom callback re-enters the contract to call approve() or other functions
 * - **State Window**: During callback, balanceOf and allowance are still at original values
 * - **Transaction 2**: Subsequent calls exploit the inconsistent state created during the callback
 * - **Accumulated Effect**: Multiple transactions can drain more tokens than intended through allowance manipulation
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Persistence**: The vulnerability exploits the fact that allowance changes persist between transactions
 * 2. **Callback Timing**: The callback can set up future exploits by manipulating persistent state
 * 3. **Sequential Dependency**: Full exploitation requires a sequence of calls that build upon each other's state changes
 * 4. **Atomic Limitation**: Single transaction cannot fully exploit due to gas limits and callback complexity
 * 
 * This creates a realistic vulnerability where attackers can manipulate allowances during the callback phase and exploit the inconsistent state in subsequent transactions.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-08-26
*/

pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnCallback {  function onBurnFrom(address operator, uint256 value) external; }
 
contract PIGX {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);


    function PIGX(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }


    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call to _from before state updates
        // This enables reentrancy through callback mechanism
        if (_from != address(0) && _isContract(_from)) {
            IBurnCallback(_from).onBurnFrom(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }

    function _isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
