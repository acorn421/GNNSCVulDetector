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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burn tracker contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added external call to `IBurnTracker(burnTracker).notifyBurn()` after balance check but before state updates
 * 2. The external call occurs before `balanceOf[msg.sender]` and `totalSupply` are decremented
 * 3. This creates a window where the contract state is inconsistent during the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker sets up malicious burn tracker contract and calls `setBurnTracker()`
 * 2. **Transaction 2**: Attacker calls `burn()` with their full balance, triggering the external call
 * 3. **During the external call**: The malicious tracker re-enters `burn()` while the original caller's balance is still unchanged
 * 4. **Transaction 3**: The re-entrant call succeeds because balance check still passes, allowing double burning
 * 
 * **Why Multiple Transactions Are Required:**
 * - The burn tracker address must be set in a prior transaction (state accumulation)
 * - The vulnerability depends on the specific sequence: setup → burn → re-enter
 * - Each burn call depends on the persistent state from previous transactions
 * - The exploit requires accumulated state where the tracker address is pre-configured
 * 
 * **Realistic Nature:**
 * - Burn tracking for analytics/compliance is a common real-world requirement
 * - The external call placement appears natural for notification purposes
 * - The vulnerability is subtle and could easily be missed in code review
 */
pragma solidity ^0.4.16;

interface IBurnTracker {
    function notifyBurn(address burner, uint256 value) external;
}

contract BXXToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    address public burnTracker;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function BXXToken() public {
        totalSupply = 1250000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "BAANX.COM LTD";
        symbol = "BXX";
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
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function setBurnTracker(address _burnTracker) public {
        burnTracker = _burnTracker;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn tracker before state updates
        if (burnTracker != address(0)) {
            IBurnTracker(burnTracker).notifyBurn(msg.sender, _value);
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
