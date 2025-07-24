/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Added an external call to notify the new owner before updating the state variables. This creates a classic reentrancy vulnerability where the new owner can re-enter the contract during the callback and potentially manipulate the ownership transfer process. The vulnerability is stateful and requires multiple transactions: first transferOwnership() to set newOwner, then acceptOwnership() which triggers the callback, and during the callback, the attacker can call transferOwnership() again before the owner state is updated, creating a race condition in the ownership transfer mechanism.
 */
pragma solidity ^0.4.16;

contract GiGi  {
   
    string public name = "GiGi";
  
    string public symbol = "GG";
  
    uint8 public decimals = 18;
  
    uint256 public totalSupply;
    bool public lockAll = false;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event FrozenFunds(address target, bool frozen);
    event OwnerUpdate(address _prevOwner, address _newOwner);

    address public owner;
   
    address internal newOwner = 0x0;
    mapping(address => bool) public frozens;
    mapping(address => uint256) public balanceOf;

    constructor() public {
        totalSupply = 100000000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        owner = msg.sender;
    }

  
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

 
    function transferOwnership(address tOwner) onlyOwner public {
        require(owner != tOwner);
        newOwner = tOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner && newOwner != 0x0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to notify new owner before state changes
        address _pendingOwner = newOwner; // Store for callback
        
        // The following check and call are modified for Solidity 0.4.x
        uint size;
        assembly { size := extcodesize(_pendingOwner) }
        if (size > 0) {
            _pendingOwner.call(
                bytes4(keccak256("onOwnershipTransferred(address,address)")), owner, _pendingOwner
            );
            // Continue regardless of callback success
        }
        
        // State changes happen AFTER external call - classic reentrancy vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = newOwner;
        newOwner = 0x0;
        emit OwnerUpdate(owner, newOwner);
    }

   
    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozens[target] = freeze;
        emit FrozenFunds(target, freeze);
    }

    function freezeAll(bool lock) onlyOwner public {
        lockAll = lock;
    }

    function contTransfer(address _to, uint256 weis) onlyOwner public {
        _transfer(this, _to, weis);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function _transfer(address _from, address _to, uint _value) internal {
       
        require(!lockAll);
      
        require(_to != 0x0);
    
        require(balanceOf[_from] >= _value);
   
        require(balanceOf[_to] + _value >= balanceOf[_to]);
      
        require(!frozens[_from]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

}
