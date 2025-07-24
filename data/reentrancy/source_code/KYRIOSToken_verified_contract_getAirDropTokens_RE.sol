/*
 * ===== SmartInject Injection Details =====
 * Function      : getAirDropTokens
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Inserted a call to recipient's `onAirDropReceived()` function before state updates, creating a classic CEI (Check-Effect-Interaction) pattern violation.
 * 
 * 2. **Preserved State Change Order**: The critical state change `airDropBlacklist[investor] = true` still occurs after the external call, creating the reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls `getAirDropTokens()`, external call triggers their malicious contract
 *    - **Reentrant Call**: Malicious contract calls `getAirDropTokens()` again during callback
 *    - **State Persistence**: `airDropBlacklist[investor]` is still false, allowing second call to pass `onlyWhitelist` modifier
 *    - **Accumulated Benefit**: Each successful call decreases `eachAirDropAmount` by 0.01 ether, so early exploitation yields more tokens
 * 
 * 4. **Stateful Nature**: The vulnerability exploits the persistent state where:
 *    - `airDropBlacklist[investor]` remains false during reentrancy
 *    - `eachAirDropAmount` decreases with each successful call
 *    - `totalAirDrop` is reduced with each airdrop
 *    - Multiple transactions can drain more tokens before blacklisting occurs
 * 
 * 5. **Realistic Implementation**: The external call simulates a common pattern of notifying recipients about received airdrops, making the vulnerability appear natural and not obviously malicious.
 * 
 * The vulnerability requires multiple function calls to be maximally effective because:
 * - Single transaction reentrancy would only allow claiming current `eachAirDropAmount` multiple times
 * - Multi-transaction approach allows claiming higher amounts before `eachAirDropAmount` decreases
 * - State accumulation across transactions enables bypassing the blacklist mechanism repeatedly
 * - The decreasing reward mechanism creates time-sensitive exploitation requiring strategic sequencing
 */
pragma solidity ^0.4.23;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
}

interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; 
}

contract KYRIOSToken {
    using SafeMath for uint256;
    string public name = "KYRIOS Token";
    string public symbol = "KRS";
    uint8 public decimals = 18;
    uint256 public totalSupply = 2000000000 ether;
    uint256 public totalAirDrop = totalSupply * 10 / 100;
    uint256 public eachAirDropAmount = 25000 ether;
    bool public airdropFinished = false;
    mapping (address => bool) public airDropBlacklist;
    mapping (address => bool) public transferBlacklist;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function KYRIOSToken() public {
        balanceOf[msg.sender] = totalSupply - totalAirDrop;
    }
    
    modifier canAirDrop() {
        require(!airdropFinished);
        _;
    }
    
    modifier onlyWhitelist() {
        require(airDropBlacklist[msg.sender] == false);
        _;
    }
    
    function airDrop(address _to, uint256 _amount) canAirDrop private returns (bool) {
        totalAirDrop = totalAirDrop.sub(_amount);
        balanceOf[_to] = balanceOf[_to].add(_amount);
        Transfer(address(0), _to, _amount);
        return true;
        
        if (totalAirDrop <= _amount) {
            airdropFinished = true;
        }
    }
    
    function inspire(address _to, uint256 _amount) private returns (bool) {
        if (!airdropFinished) {
            totalAirDrop = totalAirDrop.sub(_amount);
            balanceOf[_to] = balanceOf[_to].add(_amount);
            Transfer(address(0), _to, _amount);
            return true;
            if(totalAirDrop <= _amount){
                airdropFinished = true;
            }
        }
    }
    
    function getAirDropTokens() payable canAirDrop onlyWhitelist public {
        
        require(eachAirDropAmount <= totalAirDrop);
        
        address investor = msg.sender;
        uint256 toGive = eachAirDropAmount;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about airdrop before state changes
        if (investor.call.value(0)(bytes4(keccak256("onAirDropReceived(uint256)")), toGive)) {
            // Callback succeeded, continue with airdrop
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        airDrop(investor, toGive);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // State changes moved after external call - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (toGive > 0) {
            airDropBlacklist[investor] = true;
        }

        if (totalAirDrop == 0) {
            airdropFinished = true;
        }
        
        eachAirDropAmount = eachAirDropAmount.sub(0.01 ether);
    }
    
    function getInspireTokens(address _from, address _to,uint256 _amount) payable public{
        uint256 toGive = eachAirDropAmount * 50 / 100;
        if(toGive > totalAirDrop){
            toGive = totalAirDrop;
        }
        
        if (_amount > 0 && transferBlacklist[_from] == false) {
            transferBlacklist[_from] = true;
            inspire(_from, toGive);
        }
        if(_amount > 0 && transferBlacklist[_to] == false) {
            inspire(_to, toGive);
        }
    }
    
    function () external payable {
        getAirDropTokens();
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
        getInspireTokens(_from, _to, _value);
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
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}