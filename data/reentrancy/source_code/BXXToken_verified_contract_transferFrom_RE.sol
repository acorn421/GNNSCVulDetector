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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before allowance state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1-N**: Attacker sets up multiple allowances using approve() calls from different accounts to accumulate exploitable state
 * 2. **Transaction N+1**: Attacker initiates transferFrom() which triggers the external call to malicious recipient contract
 * 3. **Reentrancy Phase**: Malicious contract's onTokenReceived() callback can call transferFrom() again with the same allowance (since it hasn't been decremented yet)
 * 4. **State Exploitation**: Each reentrant call can drain the same allowance multiple times before the original call completes
 * 
 * The vulnerability is multi-transaction because:
 * - Allowances must be set up in previous transactions via approve() calls
 * - Each exploitation cycle requires the accumulated allowance state from prior transactions
 * - The attack builds on persistent state modifications across multiple transaction boundaries
 * - Maximum damage requires multiple preliminary transactions to establish sufficient allowances
 * 
 * This creates a realistic checks-effects-interactions violation where external calls occur before critical state updates, enabling cross-transaction reentrancy exploitation.
 */
pragma solidity ^0.4.16;

contract BXXToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

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
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Perform external call to recipient before state updates
        if (isContract(_to)) {
            // The ABI encoding and call logic are kept, but direct call, not using code.length (as unavailable in 0.4.x)
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            require(callSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
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
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }

    // Helper to check if target is a contract (since address.code.length is not available in 0.4.x)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}
