/*
 * ===== SmartInject Injection Details =====
 * Function      : write
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 13 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability with three components:
 * 
 * 1. **Business Hours Restriction**: Added time-based deployment window using block.timestamp that only allows deployments during specific hours (9 AM to 5 PM). This creates timing attacks where malicious actors can predict when deployments will be allowed/blocked.
 * 
 * 2. **Block-Based Deployment Quota**: Implemented a quota system that limits deployments to 5 per 100-block period using block.number. This requires the addition of a new state variable `mapping(uint256 => uint256) deploymentQuota` that accumulates deployment counts over time periods.
 * 
 * 3. **Timestamp-Dependent Cache Expiration**: Added cache entry expiration logic that makes cached contracts vulnerable to overwrite after 1 hour. This requires a new state variable `mapping(bytes32 => uint256) cacheTimestamps` to track when cache entries were created.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Quota Exhaustion Attack**: An attacker can monitor block numbers and make 5 quick deployments at the start of a 100-block period to exhaust the quota, preventing legitimate users from deploying until the next period.
 * 
 * 2. **Cache Poisoning via Time Manipulation**: An attacker can:
 *    - Transaction 1: Deploy a legitimate contract during business hours
 *    - Wait 1+ hours for cache expiration
 *    - Transaction 2: Deploy a malicious contract with the same bytecode hash during the next business hours window, overwriting the cached address
 * 
 * 3. **Timing-Based Denial of Service**: Attackers can coordinate attacks around the business hours restriction and quota system to systematically prevent legitimate deployments.
 * 
 * **Why Multiple Transactions Are Required:**
 * - The quota system accumulates state across multiple transactions within block periods
 * - Cache expiration requires time to pass between transactions (minimum 1 hour)
 * - Business hours restriction creates time windows that must be exploited across different transaction timing
 * - The vulnerability leverages persistent state (`deploymentQuota` and `cacheTimestamps` mappings) that builds up over multiple transactions
 * 
 * Note: This modification assumes the addition of two new state variables to the contract:
 * - `mapping(uint256 => uint256) public deploymentQuota;`
 * - `mapping(bytes32 => uint256) public cacheTimestamps;`
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
    function execute(bytes _code, bytes _data)
        public
        payable
        returns (address target, bytes32 response)
    {
        target = cache.read(_code);
        if (target == 0x0) {
            // deploy contract & store its address in cache
            target = cache.write(_code);
        }

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
    mapping(uint256 => uint256) deploymentQuota; // <--- Added declaration
    mapping(bytes32 => uint256) cacheTimestamps; // <--- Added declaration

    function read(bytes _code) public view returns (address) {
        bytes32 hash = keccak256(_code);
        return cache[hash];
    }

    function write(bytes _code) public returns (address target) {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based deployment window: only allow deployments in specific time periods
        uint256 currentHour = (block.timestamp / 3600) % 24;
        require(currentHour >= 9 && currentHour < 17, "Deployment only allowed during business hours");
        
        // Block number dependent deployment quota - accumulates over time
        uint256 blockPeriod = block.number / 100; // Reset every 100 blocks (~15 minutes)
        if (deploymentQuota[blockPeriod] >= 5) {
            revert("Deployment quota exceeded for this period");
        }
        deploymentQuota[blockPeriod]++;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        assembly {
            target := create(0, add(_code, 0x20), mload(_code))
            switch iszero(extcodesize(target))
            case 1 {
                // throw if contract failed to deploy
                revert(0, 0)
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        bytes32 hash = keccak256(_code);
        
        // Timestamp-dependent cache invalidation - older entries become vulnerable
        if (cacheTimestamps[hash] != 0 && 
            block.timestamp > cacheTimestamps[hash] + 1 hours) {
            // Cache entry expired, allow overwrite without checking
            cache[hash] = target;
            cacheTimestamps[hash] = block.timestamp;
        } else if (cacheTimestamps[hash] == 0) {
            // New cache entry
            cache[hash] = target;
            cacheTimestamps[hash] = block.timestamp;
        } else {
            // Recent cache entry exists, revert to prevent duplicate deployment
            revert("Contract already cached recently");
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
