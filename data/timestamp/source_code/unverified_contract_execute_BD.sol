/*
 * ===== SmartInject Injection Details =====
 * Function      : execute
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 14 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability that creates time-based access controls and windows for contract deployment and execution. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added State Variables for Timestamp Tracking:**
 *    - `deploymentTime`: Maps code hashes to their deployment timestamps
 *    - `lastExecutionTime`: Maps code hashes to their last execution timestamps
 *    - Time constants for deployment windows and cooldown periods
 * 
 * 2. **Time-Based Deployment Restriction:**
 *    - Contracts can only be deployed during the first half of each hour (block.timestamp % 3600 < 1800)
 *    - Creates predictable deployment windows that can be exploited
 * 
 * 3. **Freshness Check:**
 *    - Existing contracts can only be executed if deployed within the last 15 minutes
 *    - Creates a time-based access control vulnerability
 * 
 * 4. **Execution Cooldown:**
 *    - Enforces a 5-minute cooldown between executions of the same code
 *    - Uses block.timestamp for timing calculations
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Deployment Window Exploitation:**
 *    - Transaction 1: Deploy contract during favorable timestamp window (first half of hour)
 *    - Transaction 2: Execute the contract within the 15-minute freshness window
 *    - Miners can manipulate timestamps to extend or bypass these windows
 * 
 * 2. **Freshness Window Attack:**
 *    - Transaction 1: Deploy contract just before the hourly window closes
 *    - Transaction 2: Wait for timestamp manipulation to extend the freshness window
 *    - Transaction 3: Execute with extended access that shouldn't be available
 * 
 * 3. **Cooldown Bypass:**
 *    - Transaction 1: Execute contract to trigger cooldown
 *    - Transaction 2: Manipulate timestamp (via mining) to bypass the 5-minute cooldown
 *    - Transaction 3: Execute again before the intended cooldown period expires
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Persistence:** The vulnerability relies on timestamps stored in state variables that persist between transactions
 * 2. **Sequential Dependencies:** The deployment and execution phases create natural transaction boundaries
 * 3. **Time-Based Logic:** The vulnerability requires time progression between transactions to manipulate timing windows
 * 4. **Accumulative Effect:** Each transaction updates the timestamp state, enabling different exploitation paths in subsequent calls
 * 
 * **Exploitation Mechanics:**
 * 
 * - **Miner Manipulation:** Miners can set block timestamps within the allowed range (±15 seconds) to bypass time restrictions
 * - **Timestamp Prediction:** Attackers can predict future block timestamps to time their transactions optimally
 * - **State Accumulation:** The vulnerability accumulates state across multiple transactions, making single-transaction exploitation impossible
 * 
 * This creates a realistic, stateful vulnerability that requires careful timing and multiple transactions to exploit effectively.
 */
// proxy.sol - execute actions atomically through the proxy's identity

// Copyright (C) 2017  DappHub, LLC

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// SPDX-License-Identifier: MIT
pragma solidity ^0.4.23;

contract DSAuthority {
    function canCall(
        address src, address dst, bytes4 sig
    ) public view returns (bool);
}

contract DSAuthEvents {
    event LogSetAuthority (address indexed authority);
    event LogSetOwner     (address indexed owner);
}

contract DSAuth is DSAuthEvents {
    DSAuthority  public  authority;
    address      public  owner;

    constructor() public {
        owner = msg.sender;
        emit LogSetOwner(msg.sender);
    }

    function setOwner(address owner_)
        public
        auth
    {
        owner = owner_;
        emit LogSetOwner(owner);
    }

    function setAuthority(DSAuthority authority_)
        public
        auth
    {
        authority = authority_;
        emit LogSetAuthority(authority);
    }

    modifier auth {
        require(isAuthorized(msg.sender, msg.sig));
        _;
    }

    function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
        if (src == address(this)) {
            return true;
        } else if (src == owner) {
            return true;
        } else if (authority == DSAuthority(0)) {
            return false;
        } else {
            return authority.canCall(src, this, sig);
        }
    }
}

contract DSNote {
    event LogNote(
        bytes4   indexed  sig,
        address  indexed  guy,
        bytes32  indexed  foo,
        bytes32  indexed  bar,
        uint              wad,
        bytes             fax
    ) anonymous;

    modifier note {
        bytes32 foo;
        bytes32 bar;

        assembly {
            foo := calldataload(4)
            bar := calldataload(36)
        }

        emit LogNote(msg.sig, msg.sender, foo, bar, msg.value, msg.data);

        _;
    }
}

// DSProxy
// Allows code execution using a persistant identity This can be very
// useful to execute a sequence of atomic actions. Since the owner of
// the proxy can be changed, this allows for dynamic ownership models
// i.e. a multisig
contract DSProxy is DSAuth, DSNote {
    DSProxyCache public cache;  // global cache for contracts

    constructor(address _cacheAddr) public {
        require(setCache(_cacheAddr));
    }

    function() public payable {
    }

    // use the proxy to execute calldata _data on contract _code
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// Add state variables for timestamp tracking
mapping(bytes32 => uint256) public deploymentTime;
mapping(bytes32 => uint256) public lastExecutionTime;
uint256 public constant DEPLOYMENT_WINDOW = 900; // 15 minutes
uint256 public constant EXECUTION_COOLDOWN = 300; // 5 minutes

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function execute(bytes _code, bytes _data)
        public
        payable
        returns (address target, bytes32 response)
    {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        bytes32 codeHash = keccak256(_code);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        target = cache.read(_code);
        if (target == 0x0) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Time-based deployment restriction: only deploy during "safe" time windows
            require(block.timestamp % 3600 < 1800, "Deployment only allowed in first half of hour");
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            // deploy contract & store its address in cache
            target = cache.write(_code);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Record deployment timestamp
            deploymentTime[codeHash] = block.timestamp;
        } else {
            // For existing contracts, check if they're still "fresh" (deployed recently)
            require(block.timestamp <= deploymentTime[codeHash] + DEPLOYMENT_WINDOW, "Contract deployment too old");
            
            // Enforce cooldown period between executions using timestamp
            require(block.timestamp >= lastExecutionTime[codeHash] + EXECUTION_COOLDOWN, "Execution cooldown not met");
        }
        
        // Update last execution time
        lastExecutionTime[codeHash] = block.timestamp;
        
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        response = execute(target, _data);
    }

    function execute(address _target, bytes _data)
        public
        auth
        note
        payable
        returns (bytes32 response)
    {
        require(_target != 0x0);

        // call contract in current context
        assembly {
            let succeeded := delegatecall(sub(gas, 5000), _target, add(_data, 0x20), mload(_data), 0, 32)
            response := mload(0)      // load delegatecall output
            switch iszero(succeeded)
            case 1 {
                // throw if delegatecall failed
                revert(0, 0)
            }
        }
    }

    //set new cache
    function setCache(address _cacheAddr)
        public
        auth
        note
        returns (bool)
    {
        require(_cacheAddr != 0x0);        // invalid cache address
        cache = DSProxyCache(_cacheAddr);  // overwrite cache
        return true;
    }
}

// DSProxyFactory
// This factory deploys new proxy instances through build()
// Deployed proxy addresses are logged
contract DSProxyFactory {
    event Created(address indexed sender, address indexed owner, address proxy, address cache);
    mapping(address=>bool) public isProxy;
    DSProxyCache public cache = new DSProxyCache();

    // deploys a new proxy instance
    // sets owner of proxy to caller
    function build() public returns (DSProxy proxy) {
        proxy = build(msg.sender);
    }

    // deploys a new proxy instance
    // sets custom owner of proxy
    function build(address owner) public returns (DSProxy proxy) {
        proxy = new DSProxy(cache);
        emit Created(msg.sender, owner, address(proxy), address(cache));
        proxy.setOwner(owner);
        isProxy[proxy] = true;
    }
}

// DSProxyCache
// This global cache stores addresses of contracts previously deployed
// by a proxy. This saves gas from repeat deployment of the same
// contracts and eliminates blockchain bloat.

// By default, all proxies deployed from the same factory store
// contracts in the same cache. The cache a proxy instance uses can be
// changed.  The cache uses the sha3 hash of a contract's bytecode to
// lookup the address
contract DSProxyCache {
    mapping(bytes32 => address) cache;

    function read(bytes _code) public view returns (address) {
        bytes32 hash = keccak256(_code);
        return cache[hash];
    }

    function write(bytes _code) public returns (address target) {
        assembly {
            target := create(0, add(_code, 0x20), mload(_code))
            switch iszero(extcodesize(target))
            case 1 {
                // throw if contract failed to deploy
                revert(0, 0)
            }
        }
        bytes32 hash = keccak256(_code);
        cache[hash] = target;
    }
}

// ProxyRegistry
// This Registry deploys new proxy instances through DSProxyFactory.build(address) and keeps a registry of owner => proxy
contract ProxyRegistry {
    mapping(address => DSProxy) public proxies;
    DSProxyFactory factory;

    constructor(DSProxyFactory factory_) public {
        factory = factory_;
    }

    // deploys a new proxy instance
    // sets owner of proxy to caller
    function build() public returns (DSProxy proxy) {
        proxy = build(msg.sender);
    }

    // deploys a new proxy instance
    // sets custom owner of proxy
    function build(address owner) public returns (DSProxy proxy) {
        require(proxies[owner] == DSProxy(0) || proxies[owner].owner() != owner); // Not allow new proxy if the user already has one and remains being the owner
        proxy = factory.build(owner);
        proxies[owner] = proxy;
    }
}