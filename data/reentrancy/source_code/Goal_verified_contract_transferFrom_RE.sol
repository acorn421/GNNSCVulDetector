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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where the external call happens before the allowance reduction, enabling multi-transaction exploitation.
 * 
 * **Specific Changes Made:**
 * 1. Added recipient notification logic using low-level call before allowance update
 * 2. Moved the external call before `allowance[_from][msg.sender] -= _value`
 * 3. Added code length check to only call contracts (realistic pattern)
 * 4. Maintained original function signature and core functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with a malicious recipient contract
 * 2. **Reentrant Call**: The recipient's `onTokenReceived()` function is triggered before allowance is reduced
 * 3. **State Exploitation**: The malicious contract can call `transferFrom()` again while the allowance is still at the original value
 * 4. **Accumulated Damage**: Through multiple reentrant calls, the attacker can transfer more tokens than the original allowance permitted
 * 5. **State Persistence**: The vulnerability persists across multiple transactions because the allowance mapping state is not properly protected
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the recipient contract to implement `onTokenReceived()` callback
 * - The exploit involves a sequence of calls: original call → callback → reentrant calls
 * - Each reentrant call can further exploit the unchanged allowance state
 * - The attack builds up unauthorized transfers across multiple function invocations
 * - The persistent allowance state enables continued exploitation until finally updated
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and state accumulation to fully exploit, matching real-world reentrancy patterns seen in token contracts.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Goal {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 10000000000;
        uint256 public totalSupply; 

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);


        function Goal( ) public {

                totalSupply = total * 10 ** uint256(decimals);

                balanceOf[msg.sender] = totalSupply;

                name = "GOAL Coin"; 

                symbol = "GOAL";

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
        
        // Notify recipient before updating allowance (vulnerability injection)
        // _to.code.length is not available in Solidity 0.4.16, so use extcodesize
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // type signature encoding helper, since abi.encodeWithSignature is not available in 0.4.16
            // We use bytes4(keccak256(...)) and manual calldata construction
            bytes4 sig = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            // old ABI: function selector (4b), then each parameter is padded to 32 bytes
            // create calldata
            bytes memory data = new bytes(4 + 32 * 3);
            assembly {
                mstore(add(data, 32), sig)
                mstore(add(data, 36), _from)
                mstore(add(data, 68), _to)
                mstore(add(data, 100), _value)
            }
            bool callSuccess = _to.call(data);
            require(callSuccess);
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
