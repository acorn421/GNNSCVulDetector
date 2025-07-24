/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack through a mint notification callback mechanism. The exploit requires:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 - Setup Phase**: The attacker (who must be the owner) deploys a malicious contract that implements IMintNotification and calls setMintNotificationContract() to register it as the notification recipient.
 * 
 * 2. **Transaction 2 - Exploitation Phase**: The attacker calls mint() with a specific amount. The function makes an external call to the malicious contract's onMint() callback BEFORE updating the state variables (balances and totalSupply).
 * 
 * 3. **Reentrancy Attack**: The malicious contract's onMint() callback can now call mint() again recursively. Since the balances and totalSupply haven't been updated yet, the checks pass again, allowing multiple minting operations to occur within the same transaction context.
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **State Accumulation**: The vulnerability requires the attacker to first set up the malicious notification contract in a separate transaction
 * - **Persistent State Dependency**: The mintNotificationContract address must be persistently stored from the setup transaction
 * - **Sequential Exploitation**: The attack cannot be executed in a single atomic transaction because the notification contract must be deployed and registered first
 * 
 * **Stateful Nature:**
 * - The vulnerability depends on the persistent state of mintNotificationContract being set to a malicious address
 * - Each successful reentrant call accumulates more tokens in the attacker's balance
 * - The totalSupply is inflated with each recursive call, creating permanent damage to the token economics
 * 
 * **Realistic Attack Vector:**
 * This pattern is commonly seen in DeFi protocols where contracts notify external systems about minting events for integration purposes (e.g., notifying price oracles, yield farming contracts, or governance systems).
 */
pragma solidity ^0.4.11;

//------------------------------------------------------------------------------------------------
// ERC20 Standard Token Implementation, based on ERC Standard:
// https://github.com/ethereum/EIPs/issues/20
// With some inspiration from ConsenSys HumanStandardToken as well
// Copyright 2017 BattleDrome
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
// LICENSE
//
// This file is part of BattleDrome.
// 
// BattleDrome is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// BattleDrome is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with BattleDrome.  If not, see <http://www.gnu.org/licenses/>.
//------------------------------------------------------------------------------------------------


interface IMintNotification {
    function onMint(address sender, uint256 amount) external;
}

contract PFGC {
    uint256 public totalSupply;
    bool public mintable;
    string public name;
    uint256 public decimals;
    string public symbol;
    address public owner;
    address public mintNotificationContract;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function PFGC(uint256 _totalSupply, string _symbol, string _name, bool _mintable) public {
        decimals = 18;
        symbol = _symbol;
        name = _name;
        mintable = _mintable;
        owner = msg.sender;
        totalSupply = _totalSupply * (10 ** decimals);
        balances[msg.sender] = totalSupply;
        mintNotificationContract = address(0);
    }
    //Fix for short address attack against ERC20
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length == size + 4);
        _;
    } 

    function balanceOf(address _owner) constant public returns (uint256) {
        return balances[_owner];
    }

    function transfer(address _recipient, uint256 _value) onlyPayloadSize(2*32) public {
        require(balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] -= _value;
        balances[_recipient] += _value;
        Transfer(msg.sender, _recipient, _value);        
    }

    function transferFrom(address _from, address _to, uint256 _value) public {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

    function approve(address _spender, uint256 _value) public {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
    }

    function allowance(address _owner, address _spender) constant public returns (uint256) {
        return allowed[_owner][_spender];
    }

    function mint(uint256 amount) public {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    assert(amount >= 0);
    require(msg.sender == owner);
    
    // Notify external contract about minting before state update
    if (mintNotificationContract != address(0)) {
        IMintNotification(mintNotificationContract).onMint(msg.sender, amount);
    }
    
    balances[msg.sender] += amount;
    totalSupply += amount;
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    //Event which is triggered to log all transfers to this contract's event log
    event Transfer(
        address indexed _from,
        address indexed _to,
        uint256 _value
        );
        
    //Event which is triggered whenever an owner approves a new allowance for a spender.
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _value
        );

}